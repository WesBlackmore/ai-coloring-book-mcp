<?php

declare(strict_types=1);

/*
 * Optional OAuth 2.1 module (ChatGPT connector flow, PKCE S256, rotating refresh tokens). Loaded only when
 * MCP_OAUTH_ENABLED=1; PAT authentication works without it. Requires league/oauth2-server and firebase/php-jwt.
 *
 * The package has no user accounts. The host app supplies the signed-in browser account through
 *   $GLOBALS['mcp_oauth_account_resolver'] = fn(): ?array => ['id' => 'acct-1', 'label' => 'Alice'];
 * and, when nobody is signed in, MCP_OAUTH_LOGIN_URL is where the browser is sent to sign in.
 */
require_once __DIR__ . '/league.php';
require_once __DIR__ . '/store.php';

use AiColoringBookMcp\OAuth\McpOAuthClientEntity;
use AiColoringBookMcp\OAuth\McpOAuthRepositories;
use AiColoringBookMcp\OAuth\McpOAuthS256AuthCodeGrant;
use AiColoringBookMcp\OAuth\McpOAuthUserEntity;
use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use Mcp\Server\Transport\Http\OAuth\AuthorizationResult;
use Mcp\Server\Transport\Http\OAuth\JwtTokenValidator;
use Mcp\Server\Transport\Http\OAuth\JwksProviderInterface;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;

const MCP_OAUTH_CHATGPT_CLIENT_ID = 'https://chatgpt.com/oauth/client.json';
const MCP_OAUTH_SCOPE_READ = MCP_PAT_READ_SCOPE;
const MCP_OAUTH_SCOPE_WRITE = MCP_PAT_WRITE_SCOPE;
const MCP_OAUTH_SCOPE_EXPORT = MCP_PAT_EXPORT_SCOPE;
const MCP_OAUTH_AUTHORIZATION_LIFETIME_SECONDS = 900;

function mcp_oauth_http_scopes(): array
{
    return [MCP_OAUTH_SCOPE_READ, MCP_OAUTH_SCOPE_WRITE, MCP_OAUTH_SCOPE_EXPORT];
}

/** Default off. PAT authentication remains independent of this switch. */
function mcp_oauth_http_enabled(): bool
{
    return trim((string) getenv('MCP_OAUTH_ENABLED')) === '1';
}

/** @return array{app_url:string,issuer:string,resource:string,authorization_endpoint:string,token_endpoint:string,resource_metadata:string,jwks_uri:string,key_path:string,key_id:string,encryption_key:string} */
function mcp_oauth_http_config(): array
{
    $appUrl = rtrim(trim((string) getenv('MCP_PUBLIC_BASE_URL')), '/');
    $issuer = trim((string) getenv('MCP_OAUTH_ISSUER')) ?: $appUrl;
    $resource = trim((string) getenv('MCP_OAUTH_RESOURCE')) ?: ($appUrl . '/mcp');
    foreach ([$appUrl, $issuer, $resource] as $url) {
        $parts = is_string($url) ? parse_url($url) : false;
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new RuntimeException('MCP OAuth HTTPS configuration is invalid.');
        }
    }
    if ($appUrl === '' || $issuer !== $appUrl || $resource !== $appUrl . '/mcp') {
        throw new RuntimeException('MCP OAuth issuer/resource must match MCP_PUBLIC_BASE_URL and its /mcp route.');
    }
    $keyPath = trim((string) getenv('MCP_OAUTH_PRIVATE_KEY_PATH'));
    $encryptionKeyPath = trim((string) getenv('MCP_OAUTH_ENCRYPTION_KEY_PATH'));
    $keyId = trim((string) getenv('MCP_OAUTH_KEY_ID'));
    $realKeyPath = $keyPath !== '' ? realpath($keyPath) : false;
    $publicRoot = realpath(MCP_PACKAGE_ROOT . '/public');
    $encryptionKey = trim((string) getenv('MCP_OAUTH_ENCRYPTION_KEY'));
    if ($encryptionKeyPath !== '') {
        $realEncryptionKeyPath = realpath($encryptionKeyPath);
        if ($realEncryptionKeyPath === false || !is_file($realEncryptionKeyPath)
            || !is_readable($realEncryptionKeyPath)
            || ($publicRoot !== false && str_starts_with($realEncryptionKeyPath, $publicRoot . DIRECTORY_SEPARATOR))) {
            throw new RuntimeException('MCP OAuth encryption-key file is missing or unsafe.');
        }
        $encryptionKeyPermissions = fileperms($realEncryptionKeyPath);
        if ($encryptionKeyPermissions === false || ($encryptionKeyPermissions & 0077) !== 0) {
            throw new RuntimeException('MCP OAuth encryption-key file permissions must be owner-only.');
        }
        $fileKey = file_get_contents($realEncryptionKeyPath);
        if (!is_string($fileKey)) throw new RuntimeException('MCP OAuth encryption-key file cannot be read.');
        $encryptionKey = trim($fileKey);
    }
    if ($realKeyPath === false || !is_file($realKeyPath) || !is_readable($realKeyPath)
        || ($publicRoot !== false && str_starts_with($realKeyPath, $publicRoot . DIRECTORY_SEPARATOR))
        || preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $keyId) !== 1 || $encryptionKey === '') {
        throw new RuntimeException('MCP OAuth signing and encryption configuration is missing or unsafe.');
    }
    $keyPermissions = fileperms($realKeyPath);
    if ($keyPermissions === false || ($keyPermissions & 0077) !== 0) {
        throw new RuntimeException('MCP OAuth private key permissions must be owner-only.');
    }
    if (mcp_oauth_http_rsa_details($realKeyPath) === null) {
        throw new RuntimeException('MCP OAuth requires a readable RSA private key of at least 2048 bits.');
    }
    try { Key::loadFromAsciiSafeString($encryptionKey); }
    catch (Throwable) { throw new RuntimeException('MCP OAuth encryption key is invalid.'); }

    return [
        'app_url' => $appUrl, 'issuer' => $issuer, 'resource' => $resource,
        'authorization_endpoint' => $appUrl . '/oauth/authorize',
        'token_endpoint' => $appUrl . '/oauth/token',
        'resource_metadata' => $appUrl . '/.well-known/oauth-protected-resource/mcp',
        'jwks_uri' => $appUrl . '/oauth/jwks.json', 'key_path' => $realKeyPath,
        'key_id' => $keyId, 'encryption_key' => $encryptionKey,
    ];
}

/** Return public RSA components only for a valid 2048-bit-or-stronger private key. */
function mcp_oauth_http_rsa_details(string $keyPath): ?array
{
    $contents = file_get_contents($keyPath);
    if (!is_string($contents)) return null;
    $privateKey = openssl_pkey_get_private($contents);
    $details = $privateKey !== false ? openssl_pkey_get_details($privateKey) : false;
    if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA
        || (int) ($details['bits'] ?? 0) < 2048
        || !isset($details['rsa']['n'], $details['rsa']['e'])) return null;
    return $details;
}

function mcp_oauth_http_schema_ready(?PDO $pdo = null): bool
{
    try {
        $pdo ??= mcp_db();
        foreach (['mcp_oauth_grants','mcp_oauth_authorization_codes','mcp_oauth_access_tokens',
            'mcp_oauth_refresh_tokens','mcp_oauth_cimd_cache','mcp_oauth_pending_authorizations'] as $table) {
            $query = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?");
            $query->execute([$table]);
            if ($query->fetchColumn() === false) return false;
        }
        return true;
    } catch (Throwable) { return false; }
}

/** @param array<string,mixed> $document */
function mcp_oauth_validate_chatgpt_cimd(string $clientId, array $document): ?McpOAuthClientEntity
{
    if (!hash_equals(MCP_OAUTH_CHATGPT_CLIENT_ID, $clientId)
        || ($document['client_id'] ?? null) !== MCP_OAUTH_CHATGPT_CLIENT_ID
        || !is_string($document['client_name'] ?? null)
        || trim($document['client_name']) === '' || mb_strlen($document['client_name']) > 120
        || !is_array($document['redirect_uris'] ?? null) || $document['redirect_uris'] === []) {
        return null;
    }
    $authMethods = $document['token_endpoint_auth_methods_supported'] ?? null;
    if (!is_array($authMethods)) {
        $single = $document['token_endpoint_auth_method'] ?? null;
        $authMethods = is_string($single) ? [$single] : [];
    }
    if (!in_array('none', $authMethods, true)) return null;
    $redirects = [];
    foreach ($document['redirect_uris'] as $uri) {
        if (!is_string($uri) || strlen($uri) > 2048) return null;
        $parts = parse_url($uri);
        $path = is_array($parts) ? (string) ($parts['path'] ?? '') : '';
        $allowedPath = $path === '/connector_platform_oauth_redirect'
            || preg_match('#^/connector/oauth/[A-Za-z0-9_-]{1,128}$#D', $path) === 1;
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || strtolower((string) ($parts['host'] ?? '')) !== 'chatgpt.com'
            || !$allowedPath || isset($parts['port']) || isset($parts['query'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) return null;
        $redirects[] = $uri;
    }
    $redirects = array_values(array_unique($redirects));
    try {
        return new McpOAuthClientEntity($clientId, trim($document['client_name']), $redirects);
    } catch (Throwable) { return null; }
}

function mcp_oauth_http_chatgpt_client(string $clientId, ?PDO $pdo = null): ?McpOAuthClientEntity
{
    if (!hash_equals(MCP_OAUTH_CHATGPT_CLIENT_ID, $clientId)) return null;
    $pdo ??= mcp_db();
    $now = gmdate('Y-m-d H:i:s');
    $query = $pdo->prepare('SELECT metadata_json,metadata_sha256,expires_at FROM mcp_oauth_cimd_cache WHERE client_id=?');
    $query->execute([$clientId]);
    $cached = $query->fetch(PDO::FETCH_ASSOC);
    if (is_array($cached) && (string) $cached['expires_at'] > $now
        && hash_equals((string) $cached['metadata_sha256'], hash('sha256', (string) $cached['metadata_json']))) {
        $decoded = json_decode((string) $cached['metadata_json'], true);
        if (is_array($decoded)) {
            $client = mcp_oauth_validate_chatgpt_cimd($clientId, $decoded);
            if ($client !== null) return $client;
        }
    }
    if (!function_exists('curl_init')) return null;
    $body = '';
    $handle = curl_init(MCP_OAUTH_CHATGPT_CLIENT_ID);
    if ($handle === false) return null;
    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'AI-Coloring-Book-MCP-OAuth/1.0',
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
        CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body): int {
            if (strlen($body) + strlen($chunk) > 32768) return 0;
            $body .= $chunk;
            return strlen($chunk);
        },
    ]);
    $ok = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    $contentType = strtolower((string) curl_getinfo($handle, CURLINFO_CONTENT_TYPE));
    curl_close($handle);
    if ($ok !== true || $status !== 200 || !str_starts_with($contentType, 'application/json')) return null;
    $document = json_decode($body, true, 32, JSON_BIGINT_AS_STRING);
    if (!is_array($document)) return null;
    $client = mcp_oauth_validate_chatgpt_cimd($clientId, $document);
    if ($client === null) return null;
    $encoded = json_encode($document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $save = $pdo->prepare('INSERT INTO mcp_oauth_cimd_cache
        (client_id,metadata_json,metadata_sha256,fetched_at,expires_at)
        VALUES (:client_id,:json,:hash,:fetched,:expires)
        ON CONFLICT(client_id) DO UPDATE SET metadata_json=excluded.metadata_json,
            metadata_sha256=excluded.metadata_sha256,fetched_at=excluded.fetched_at,expires_at=excluded.expires_at');
    $save->execute(['client_id' => $clientId, 'json' => $encoded, 'hash' => hash('sha256', $encoded),
        'fetched' => $now, 'expires' => gmdate('Y-m-d H:i:s', time() + 300)]);
    return $client;
}

/** @return array{0:AuthorizationServer,1:McpOAuthRepositories} */
function mcp_oauth_http_server(McpOAuthClientEntity $client, ?PDO $pdo = null): array
{
    $config = mcp_oauth_http_config();
    $pdo ??= mcp_db();
    $repositories = new McpOAuthRepositories($pdo, $client, $config['issuer'], $config['resource'], $config['key_id']);
    $server = new AuthorizationServer($repositories, $repositories, $repositories,
        new CryptKey($config['key_path']), Key::loadFromAsciiSafeString($config['encryption_key']));
    $authCodeGrant = new McpOAuthS256AuthCodeGrant($repositories, $repositories, new DateInterval('PT5M'));
    $authCodeGrant->setRefreshTokenTTL(new DateInterval('P30D'));
    $server->enableGrantType($authCodeGrant, new DateInterval('PT10M'));
    // The second enableGrantType argument is the access-token lifetime. Keep access
    // tokens short-lived and set the rotating refresh-token inactivity window explicitly.
    $refreshGrant = new RefreshTokenGrant($repositories);
    $refreshGrant->setRefreshTokenTTL(new DateInterval('P30D'));
    $server->enableGrantType($refreshGrant, new DateInterval('PT10M'));
    return [$server, $repositories];
}

/** Route dispatcher is called before the main front controller opens a session. */
function mcp_oauth_http_route(string $requestPath): never
{
    header('Cache-Control: no-store, private, max-age=0');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    if ($requestPath === '/oauth/token') {
        // Record enough to distinguish a client/proxy mismatch from an OAuth
        // rejection, without ever logging the request body, headers or tokens.
        $requestMethod = strtoupper(trim((string) ($_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN')));
        $method = in_array($requestMethod, ['GET', 'POST'], true) ? $requestMethod : 'other';
        $contentType = strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
        $contentTypeClass = $contentType === 'application/x-www-form-urlencoded' ? 'form'
            : ($contentType === '' ? 'missing' : 'other');
        error_log('ai-coloring-book-mcp OAuth token route received: method=' . $method
            . ' content_type=' . $contentTypeClass);
    }
    if (!mcp_oauth_http_enabled()) { http_response_code(404); exit; }
    try {
        $config = mcp_oauth_http_config();
        if (!mcp_oauth_http_schema_ready()) { http_response_code(503); exit; }
        if (in_array($requestPath, ['/.well-known/oauth-authorization-server',
            '/.well-known/oauth-protected-resource/mcp', '/oauth/jwks.json'], true)
            && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
            header('Allow: GET'); http_response_code(405); exit;
        }
        if ($requestPath === '/.well-known/oauth-authorization-server') {
            mcp_oauth_http_json([
                'issuer' => $config['issuer'],
                'authorization_endpoint' => $config['authorization_endpoint'],
                'token_endpoint' => $config['token_endpoint'],
                'jwks_uri' => $config['jwks_uri'],
                'response_types_supported' => ['code'],
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'code_challenge_methods_supported' => ['S256'],
                'token_endpoint_auth_methods_supported' => ['none'],
                'client_id_metadata_document_supported' => true,
                'authorization_response_iss_parameter_supported' => true,
                'scopes_supported' => mcp_oauth_http_scopes(),
            ], 200, 'public, max-age=300');
        }
        if ($requestPath === '/.well-known/oauth-protected-resource/mcp') {
            mcp_oauth_http_json([
                'resource' => $config['resource'],
                'authorization_servers' => [$config['issuer']],
                'scopes_supported' => mcp_oauth_http_scopes(),
                'bearer_methods_supported' => ['header'],
            ], 200, 'public, max-age=300');
        }
        if ($requestPath === '/oauth/jwks.json') { mcp_oauth_http_jwks($config); }
        if ($requestPath === '/oauth/authorize') { mcp_oauth_http_authorize($config); }
        if ($requestPath === '/oauth/token') { mcp_oauth_http_token($config); }
        http_response_code(404);
        exit;
    } catch (Throwable $error) {
        error_log('ai-coloring-book-mcp OAuth route failure: ' . get_class($error));
        http_response_code(503);
        exit;
    }
}

/** @param array<string,mixed> $payload */
function mcp_oauth_http_json(array $payload, int $status, string $cacheControl): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: ' . $cacheControl);
    echo json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/** @param array<string,string> $config */
function mcp_oauth_http_jwks(array $config): never
{
    $details = mcp_oauth_http_rsa_details($config['key_path']);
    if ($details === null) {
        http_response_code(503);
        exit;
    }
    mcp_oauth_http_json(['keys' => [[
        'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $config['key_id'],
        'n' => mcp_oauth_http_b64url($details['rsa']['n']), 'e' => mcp_oauth_http_b64url($details['rsa']['e']),
    ]]], 200, 'public, max-age=300');
}

function mcp_oauth_http_b64url(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

/** MCP's private filesystem namespace is a 96-bit hash of an authenticated grant binding. */
function mcp_oauth_http_session_id(string $grantBinding): string
{
    return substr(hash('sha256', $grantBinding), 0, 24);
}

final class McpOAuthLocalJwksProvider implements JwksProviderInterface
{
    public function __construct(private array $jwks) {}
    public function getJwks(string $issuer, ?string $jwksUri = null): array { return $this->jwks; }
}

/** Validate cryptographic token claims, then live SQLite grant/session/revocation state. */
function mcp_oauth_authenticate_access_token(string $token, ?PDO $pdo = null): ?array
{
    $config = mcp_oauth_http_config();
    $details = mcp_oauth_http_rsa_details($config['key_path']);
    if ($details === null) return null;
    $validator = new JwtTokenValidator($config['issuer'], $config['resource'], new McpOAuthLocalJwksProvider([
        'keys' => [[
            'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $config['key_id'],
            'n' => mcp_oauth_http_b64url($details['rsa']['n']), 'e' => mcp_oauth_http_b64url($details['rsa']['e']),
        ]],
    ]), $config['jwks_uri'], ['RS256'], 'scope');
    $result = $validator->validate($token);
    if (!$result->isAllowed()) {
        // Never log the token, claims, headers or arbitrary validator messages.
        $reason = match ($result->getErrorDescription()) {
            'Token has expired.' => 'expired',
            'Token is not yet valid.' => 'not_yet_valid',
            'Token issuer mismatch.' => 'issuer',
            'Token audience mismatch.' => 'audience',
            'Token signature verification failed.' => 'signature',
            default => 'validation',
        };
        error_log('ai-coloring-book-mcp OAuth access rejected: reason=' . $reason);
        return null;
    }
    $claims = $result->getAttributes()['oauth.claims'] ?? [];
    $accountId = $claims['sub'] ?? null;
    $tokenId = $claims['jti'] ?? null;
    if (!is_string($accountId) || !mcp_account_id_valid($accountId) || !is_string($tokenId)) return null;
    $principal = mcp_oauth_store_validate_access_token($tokenId, $accountId, $config['resource'], [MCP_OAUTH_SCOPE_READ], $pdo);
    if ($principal === null) {
        error_log('ai-coloring-book-mcp OAuth access rejected: reason=durable_state');
        return null;
    }
    // Protocol state belongs to the validated user/client/resource/grant, not one
    // short-lived JWT. Authentication and scopes are still checked on every call.
    $sessionBinding = json_encode(['oauth-grant-session-v1', $principal['account_id'],
        $principal['client_id'], $principal['resource'], $principal['grant_id']], JSON_THROW_ON_ERROR);
    return ['account_id' => $principal['account_id'], 'token_id' => mcp_oauth_http_session_id($sessionBinding),
        'grant_id' => $principal['grant_id'], 'client_id' => $principal['client_id'],
        'scopes' => $principal['scopes']];
}

/** Build a PSR request with explicit limits for the standard form-encoded token endpoint. */
function mcp_oauth_http_psr_request(string $path): ServerRequestInterface
{
    $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($length < 0 || $length > 32768) throw OAuthServerException::invalidRequest('request', 'Request body is too large.');
    $body = file_get_contents('php://input', false, null, 0, 32769);
    if (!is_string($body) || strlen($body) > 32768) throw OAuthServerException::invalidRequest('request', 'Request body is too large.');
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (str_starts_with($key, 'HTTP_')) $headers[str_replace('_', '-', substr($key, 5))] = (string) $value;
    }
    if (isset($_SERVER['CONTENT_TYPE'])) $headers['Content-Type'] = (string) $_SERVER['CONTENT_TYPE'];
    $request = new ServerRequest((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'), $path, $headers, $body,
        (string) ($_SERVER['SERVER_PROTOCOL'] ?? '1.1'), $_SERVER);
    return $request->withQueryParams($_GET)->withParsedBody($_POST);
}

/** The signed-in host account for this browser, from the host's resolver. Null when nobody is signed in. */
function mcp_oauth_http_account(): ?array
{
    $resolver = $GLOBALS['mcp_oauth_account_resolver'] ?? null;
    if (!is_callable($resolver)) return null;
    $account = $resolver();
    if (!is_array($account) || !is_string($account['id'] ?? null) || !mcp_account_id_valid($account['id'])) return null;
    return ['id' => $account['id'], 'label' => (string) ($account['label'] ?? $account['id'])];
}

/** A short-lived browser session for the consent step: the pending request and the CSRF token. */
function mcp_oauth_http_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => mcp_request_is_secure()]);
    session_start();
}

function mcp_oauth_http_csrf_token(): string
{
    mcp_oauth_http_session();
    if (!is_string($_SESSION['mcp_oauth_csrf'] ?? null)) $_SESSION['mcp_oauth_csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['mcp_oauth_csrf'];
}

function mcp_oauth_http_check_csrf(): void
{
    $sent = $_POST['csrf'] ?? null;
    if (!is_string($sent) || !is_string($_SESSION['mcp_oauth_csrf'] ?? null)
        || !hash_equals($_SESSION['mcp_oauth_csrf'], $sent)) {
        http_response_code(400);
        exit('Invalid request. Restart the connection from ChatGPT.');
    }
}

/** Parse and validate the authorization request before any login redirect or session parking. */
function mcp_oauth_http_authorize(array $config): never
{
    mcp_oauth_http_session();
    $method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if ($method === 'POST') { mcp_oauth_http_consent($config); }
    if ($method !== 'GET') { header('Allow: GET, POST'); http_response_code(405); exit; }
    $request = mcp_oauth_http_psr_request('/oauth/authorize');
    $params = $request->getQueryParams();
    // The normal sign-in and Google callback return to this same route without
    // the original query string. Resume only the validated, unconsented request
    // parked in this browser session; never recover OAuth parameters from a URL
    // or other client-controlled storage after login.
    if ($params === []) {
        $pending = $_SESSION['mcp_oauth_authorization'] ?? null;
        $requestedAt = is_array($pending) ? ($pending['requested_at'] ?? null) : null;
        $pendingParams = is_array($pending) ? ($pending['params'] ?? null) : null;
        $pendingUserId = is_array($pending) ? ($pending['browser_account_id'] ?? null) : null;
        $resumeUser = is_string($pendingUserId) ? mcp_oauth_http_account() : null;
        $sameBoundUser = is_string($pendingUserId) && $resumeUser !== null
            && $resumeUser['id'] === $pendingUserId;
        if (is_array($pending) && ($pendingUserId === null || $sameBoundUser)
            && is_int($requestedAt) && $requestedAt <= time()
            && $requestedAt >= time() - MCP_OAUTH_AUTHORIZATION_LIFETIME_SECONDS
            && is_array($pendingParams)) {
            $params = $pendingParams;
            $request = $request->withQueryParams($params);
        } else {
            // A stray queryless request must not destroy an otherwise valid
            // authorization that is waiting for its same-session consent POST.
            // A later POST remains bound to the original user and expiry.
            $reason = !is_array($pending) ? 'pending-missing'
                : (!is_int($requestedAt) ? 'timestamp-invalid'
                : ($requestedAt > time() ? 'timestamp-future'
                : ($requestedAt < time() - MCP_OAUTH_AUTHORIZATION_LIFETIME_SECONDS ? 'request-expired'
                : ($pendingUserId !== null && !$sameBoundUser ? 'account-session-mismatch'
                : 'pending-parameters-invalid'))));
            $sessionFingerprint = substr(hash_hmac('sha256', session_id(), $config['encryption_key']), 0, 16);
            error_log('ai-coloring-book-mcp OAuth queryless request not resumed: ' . $reason
                . ' session=' . $sessionFingerprint);
            http_response_code(400); exit('OAuth authorization request expired. Restart the connection from ChatGPT.');
        }
    }
    if (strlen((string) ($_SERVER['QUERY_STRING'] ?? '')) > 8192) {
        http_response_code(400); exit('Invalid OAuth authorization request.');
    }
    // ChatGPT includes the standard OAuth localization hint `ui_locales` in
    // authorization requests. It does not affect authorization semantics, but
    // rejecting it prevents otherwise valid clients from reaching consent.
    $requiredParams = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state',
        'code_challenge', 'code_challenge_method', 'resource'];
    $allowedParams = [...$requiredParams, 'ui_locales'];
    if (array_diff(array_keys($params), $allowedParams) !== []
        || array_diff($requiredParams, array_keys($params)) !== []) {
        http_response_code(400); exit('Invalid OAuth authorization request.');
    }
    // PHP's normal query parser discards duplicate scalar keys. Reject duplicates
    // from the original query string rather than allowing ambiguous parameters.
    $seen = [];
    foreach (explode('&', (string) ($_SERVER['QUERY_STRING'] ?? '')) as $pair) {
        if ($pair === '') continue;
        [$rawKey] = array_pad(explode('=', $pair, 2), 2, '');
        $key = urldecode($rawKey);
        if (isset($seen[$key]) || str_contains($key, '[') || str_contains($key, ']')) {
            http_response_code(400); exit('Invalid OAuth authorization request.');
        }
        $seen[$key] = true;
    }
    $clientId = $params['client_id'] ?? null;
    if (!is_string($clientId) || !hash_equals(MCP_OAUTH_CHATGPT_CLIENT_ID, $clientId)) {
        http_response_code(400); exit('Unsupported OAuth client.');
    }
    $client = mcp_oauth_http_chatgpt_client($clientId);
    if ($client === null) { http_response_code(503); exit('ChatGPT client metadata is temporarily unavailable.'); }
    try {
        [$server, $repositories] = mcp_oauth_http_server($client);
        $repositories->assertAuthorizationResource($request);
        $authorization = $server->validateAuthorizationRequest($request);
    } catch (OAuthServerException) { http_response_code(400); exit('Invalid OAuth authorization request.'); }
    $safeParams = [];
    foreach (['client_id','redirect_uri','response_type','scope','state','code_challenge','code_challenge_method','resource'] as $key) {
        $value = $params[$key] ?? null;
        if (!is_string($value)) { http_response_code(400); exit('Invalid OAuth authorization request.'); }
        $safeParams[$key] = $value;
    }
    if (isset($params['ui_locales']) && (!is_string($params['ui_locales'])
        || strlen($params['ui_locales']) > 128
        || preg_match('/^[A-Za-z0-9-]+(?: [A-Za-z0-9-]+)*$/D', $params['ui_locales']) !== 1)) {
        http_response_code(400); exit('Invalid OAuth authorization request.');
    }
    // OpenAI's plugin portal wraps its draft-connection context in OAuth state;
    // the current relay is longer than a typical ChatGPT user-connection state.
    // Keep a strict bound, but leave room for that opaque, signed client value.
    if (strlen($safeParams['state']) < 16 || strlen($safeParams['state']) > 2048
        || preg_match('/[\x00-\x1F\x7F]/', $safeParams['state']) === 1) {
        http_response_code(400); exit('Invalid OAuth authorization state.');
    }
    $_SESSION['mcp_oauth_authorization'] = [
        'params' => $safeParams, 'requested_at' => time(),
        'browser_account_id' => null,
    ];
    $user = mcp_oauth_http_account();
    if ($user === null) {
        $_SESSION['mcp_oauth_return_url'] = '/oauth/authorize';
        $login = trim((string) getenv('MCP_OAUTH_LOGIN_URL'));
        if ($login === '') {
            http_response_code(401);
            exit('No signed-in account. Set MCP_OAUTH_LOGIN_URL and register an mcp_oauth_account_resolver.');
        }
        header('Location: ' . $login, true, 302);
        exit;
    }
    $requestedScopes = array_map(static fn ($scope): string => $scope->getIdentifier(), $authorization->getScopes());
    if (!in_array(MCP_OAUTH_SCOPE_READ, $requestedScopes, true)
        || array_diff($requestedScopes, mcp_oauth_http_scopes()) !== []) {
        unset($_SESSION['mcp_oauth_authorization']);
        mcp_oauth_http_complete_authorization($server, $authorization, $user['id'], false, $config);
    }
    $_SESSION['mcp_oauth_authorization']['browser_account_id'] = $user['id'];
    $sessionBinding = hash_hmac('sha256', session_id(), $config['encryption_key']);
    $requestHandle = mcp_oauth_store_create_pending_authorization($safeParams, $user['id'],
        $sessionBinding, time() + MCP_OAUTH_AUTHORIZATION_LIFETIME_SECONDS);
    $sessionFingerprint = substr(hash_hmac('sha256', session_id(), $config['encryption_key']), 0, 16);
    error_log('ai-coloring-book-mcp OAuth consent rendered: session=' . $sessionFingerprint . ' pending=durable');
    mcp_oauth_http_render_consent($user, $authorization->getScopes(), $requestHandle);
}

/** @param array<string,mixed> $user @param list<\League\OAuth2\Server\Entities\ScopeEntityInterface> $scopes */
function mcp_oauth_http_render_consent(array $user, array $scopes, string $requestHandle): never
{
    $labels = [MCP_OAUTH_SCOPE_READ => 'Read your coloring books and generation progress.',
        MCP_OAUTH_SCOPE_WRITE => 'Create coloring books and start generation under your account.',
        MCP_OAUTH_SCOPE_EXPORT => 'Prepare and retrieve PDF exports for your coloring books.'];
    $names = [];
    foreach ($scopes as $scope) {
        $id = $scope->getIdentifier();
        if (!isset($labels[$id])) { http_response_code(400); exit('Unsupported permissions requested.'); }
        $names[$id] = $labels[$id];
    }
    $csrf = htmlspecialchars(mcp_oauth_http_csrf_token(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    header('Content-Type: text/html; charset=utf-8');
    header('Referrer-Policy: no-referrer');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="color-scheme" content="light">'
        . '<title>Connect AI Coloring Book MCP</title><style>'
        . ':root{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17352f;background:#f4f7f5;'
        . 'font-synthesis:none;text-rendering:optimizeLegibility}*{box-sizing:border-box}body{margin:0;min-height:100vh;'
        . 'padding:clamp(20px,6vw,64px) 16px;display:grid;place-items:center;background:linear-gradient(145deg,#f5f8f6,#edf4f1)}'
        . '.card{width:min(100%,560px);background:#fff;border:1px solid #dce7e1;border-radius:20px;'
        . 'box-shadow:0 18px 55px rgba(16,59,47,.09);padding:clamp(24px,6vw,44px)}'
        . '.brand{display:flex;align-items:center;gap:12px;margin-bottom:32px;color:#17352f;font-size:15px;font-weight:700;letter-spacing:.01em}'
        . '.brand img{width:38px;height:38px;object-fit:contain}.eyebrow{margin:0 0 8px;color:#587269;font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}'
        . 'h1{margin:0 0 18px;font-size:clamp(28px,6vw,38px);line-height:1.12;letter-spacing:-.035em;color:#123d32}'
        . '.identity{margin:0 0 28px;color:#52675f;font-size:15px;line-height:1.55;overflow-wrap:anywhere}.identity strong{color:#263e36}'
        . '.permissions{padding:20px;background:#f5f8f6;border:1px solid #e1ebe5;border-radius:14px;margin:0 0 22px}'
        . '.permissions h2{font-size:16px;margin:0 0 14px;color:#203d33}.permissions ul{list-style:none;padding:0;margin:0;display:grid;gap:12px}'
        . '.permissions li{display:flex;gap:10px;align-items:flex-start;font-size:15px;line-height:1.5}.check{color:#13826c;font-weight:800;flex:none}'
        . '.notice{font-size:14px;line-height:1.65;color:#53675f;margin:0 0 26px}.actions{display:flex;gap:12px;flex-wrap:wrap}'
        . 'button{font:inherit;font-size:15px;font-weight:700;border-radius:10px;padding:12px 18px;min-height:48px;cursor:pointer}'
        . '.allow{background:#087b65;color:white;border:1px solid #087b65;flex:1}.allow:hover{background:#066552}'
        . '.cancel{background:#fff;color:#29463c;border:1px solid #bdcec5}.cancel:hover{background:#f4f7f5}'
        . 'button:focus-visible{outline:3px solid #e3a357;outline-offset:3px}.foot{margin:26px 0 0;padding-top:18px;border-top:1px solid #e6ede9;'
        . 'font-size:12px;line-height:1.6;color:#71827b}.foot a{color:#176b58;text-underline-offset:2px}'
        . '@media(max-width:420px){.actions{flex-direction:column}.actions button{width:100%}}</style></head><body>'
        . '<main class="card"><div class="brand"><span>AI Coloring Book MCP</span></div>'
        . '<p class="eyebrow">Secure account connection</p><h1>Connect to ChatGPT</h1>'
        . '<p class="identity">Signed in as <strong>' . htmlspecialchars((string) $user['label'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</strong>.</p>'
        . '<section class="permissions" aria-labelledby="permission-heading"><h2 id="permission-heading">ChatGPT is requesting</h2><ul>';
    foreach ($names as $description) echo '<li><span class="check" aria-hidden="true">✓</span><span>'
        . htmlspecialchars($description, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</span></li>';
    echo '</ul></section><p class="notice">Your existing account and its access rules still apply. '
        . 'You can disconnect ChatGPT from your account settings at any time.</p>'
        . '<form method="post" action="/oauth/authorize"><input type="hidden" name="csrf" value="' . $csrf . '">'
        . '<input type="hidden" name="request_id" value="' . htmlspecialchars($requestHandle, ENT_QUOTES, 'UTF-8') . '">'
        . '<div class="actions"><button class="allow" name="decision" value="approve">Allow ChatGPT</button>'
        . '<button class="cancel" name="decision" value="deny">Cancel</button></div></form>'
        . '<p class="foot">You can revoke access from your account settings.</p></main></body></html>';
    exit;
}

/** Complete an authorization result only through the already validated callback, adding issuer identification. */
function mcp_oauth_http_complete_authorization($server, $authorization, string $accountId,
    bool $approved, array $config): never
{
    $authorization->setUser(new McpOAuthUserEntity($accountId));
    $authorization->setAuthorizationApproved($approved);
    try {
        $response = $server->completeAuthorizationRequest($authorization, new Response());
        mcp_oauth_http_redirect_with_issuer($response->getHeaderLine('Location'), $config);
    } catch (OAuthServerException $error) {
        // League represents an explicit user denial as a redirect-bearing OAuth error.
        // Generate that standards-shaped callback, then add RFC 9207 issuer identification.
        if ($error->getRedirectUri() !== null) {
            $errorResponse = $error->generateHttpResponse(new Response());
            mcp_oauth_http_redirect_with_issuer($errorResponse->getHeaderLine('Location'), $config);
        }
        throw $error;
    }
}

function mcp_oauth_http_consent(array $config): never
{
    mcp_oauth_http_check_csrf();
    $user = mcp_oauth_http_account();
    $requestHandle = $_POST['request_id'] ?? null;
    $sessionBinding = hash_hmac('sha256', session_id(), $config['encryption_key']);
    $params = is_string($requestHandle) && $user !== null
        ? mcp_oauth_store_find_pending_authorization($requestHandle, $sessionBinding, $user['id'])
        : null;
    if (!is_array($params)) {
        // Keep authorization details out of logs; the session fingerprint and fixed reason are
        // sufficient to distinguish missing, expired, cross-session and replayed consent handles.
        $sessionFingerprint = substr($sessionBinding, 0, 16);
        error_log('ai-coloring-book-mcp OAuth consent rejected: pending-request-unavailable session=' . $sessionFingerprint);
        unset($_SESSION['mcp_oauth_authorization']);
        http_response_code(400); exit('OAuth authorization expired; restart the connection from ChatGPT.');
    }
    $client = mcp_oauth_http_chatgpt_client((string) $params['client_id']);
    if ($client === null) { unset($_SESSION['mcp_oauth_authorization']); http_response_code(503); exit; }
    [$server, $repositories] = mcp_oauth_http_server($client);
    $request = (new ServerRequest('GET', $config['authorization_endpoint']))->withQueryParams($params);
    try {
        $repositories->assertAuthorizationResource($request);
        $authorization = $server->validateAuthorizationRequest($request);
        $scopes = array_map(static fn ($scope): string => $scope->getIdentifier(), $authorization->getScopes());
        $scopesAllowed = in_array(MCP_OAUTH_SCOPE_READ, $scopes, true)
            && count(array_diff($scopes, [MCP_OAUTH_SCOPE_READ, MCP_OAUTH_SCOPE_WRITE, MCP_OAUTH_SCOPE_EXPORT])) === 0;
        // Keep the production trail useful without recording account details, OAuth state,
        // authorization codes, or raw request parameters. This distinguishes an explicit
        // denial from a scope-policy denial when ChatGPT later reports access_denied.
        $postedDecision = (string) ($_POST['decision'] ?? '');
        $decisionClass = $postedDecision === 'approve' ? 'approve'
            : ($postedDecision === 'deny' ? 'deny' : ($postedDecision === '' ? 'missing' : 'other'));
        $scopeClass = !$scopesAllowed ? 'unsupported'
            : (count($scopes) === 1 && $scopes[0] === MCP_OAUTH_SCOPE_READ ? 'read_only' : 'known_multi');
        error_log('ai-coloring-book-mcp OAuth consent decision: decision=' . $decisionClass
            . ' scope=' . $scopeClass);
        if (!mcp_oauth_store_consume_pending_authorization($requestHandle, $sessionBinding, $user['id'])) {
            unset($_SESSION['mcp_oauth_authorization']);
            http_response_code(400); exit('OAuth authorization expired; restart the connection from ChatGPT.');
        }
        if ($postedDecision !== 'approve' || !$scopesAllowed) {
            unset($_SESSION['mcp_oauth_authorization']);
            mcp_oauth_http_complete_authorization($server, $authorization, $user['id'], false, $config);
        }
        $pdo = mcp_db();
        mcp_oauth_store_begin($pdo);
        try {
            $grantId = bin2hex(random_bytes(24));
            $insertGrant = $pdo->prepare('INSERT INTO mcp_oauth_grants
                (grant_id,account_id,client_id,resource,scopes)
                VALUES (:grant_id,:account_id,:client_id,:resource,:scopes)');
            $insertGrant->execute(['grant_id' => $grantId, 'account_id' => $user['id'],
                'client_id' => $client->getIdentifier(), 'resource' => $config['resource'],
                'scopes' => implode(' ', $scopes)]);
            $repositories->setAuthorizationContext($user['id'], $grantId,
                (string) $params['code_challenge'], (string) $params['code_challenge_method']);
            $authorization->setUser(new McpOAuthUserEntity($user['id']));
            $authorization->setAuthorizationApproved(true);
            $response = $server->completeAuthorizationRequest($authorization, new Response());
            $callbackLocation = $response->getHeaderLine('Location');
            $pdo->exec('COMMIT');
        } catch (Throwable $error) {
            mcp_oauth_store_rollback($pdo);
            throw $error;
        }
        unset($_SESSION['mcp_oauth_authorization']);
        mcp_oauth_http_redirect_with_issuer($callbackLocation, $config);
    } catch (OAuthServerException) {
        unset($_SESSION['mcp_oauth_authorization']);
        http_response_code(400); exit('OAuth consent could not be completed. Restart the connection from ChatGPT.');
    } catch (Throwable $error) {
        unset($_SESSION['mcp_oauth_authorization']);
        error_log('ai-coloring-book-mcp OAuth consent failure: ' . get_class($error));
        http_response_code(503); exit('OAuth consent is temporarily unavailable.');
    }
}

/** Never redirect to anything except the validated CIMD redirect; add RFC 9207 issuer identification. */
function mcp_oauth_http_issuer_callback_location(string $location, array $config): ?string
{
    $parts = parse_url($location);
    $path = is_array($parts) ? (string) ($parts['path'] ?? '') : '';
    $allowedPath = $path === '/connector_platform_oauth_redirect'
        || preg_match('#^/connector/oauth/[A-Za-z0-9_-]{1,128}$#D', $path) === 1;
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host']) || $parts['scheme'] !== 'https'
        || strtolower((string) $parts['host']) !== 'chatgpt.com' || !$allowedPath
        || isset($parts['port']) || isset($parts['user']) || isset($parts['pass'])
        || isset($parts['fragment'])) return null;
    parse_str((string) ($parts['query'] ?? ''), $callbackQuery);
    if (array_key_exists('iss', $callbackQuery)) return null;
    $separator = str_contains($location, '?') ? '&' : '?';
    return $location . $separator . 'iss=' . rawurlencode($config['issuer']);
}

function mcp_oauth_http_redirect_with_issuer(string $location, array $config): never
{
    $callback = mcp_oauth_http_issuer_callback_location($location, $config);
    if ($callback === null) {
        error_log('ai-coloring-book-mcp OAuth callback rejected: destination-not-allowlisted');
        http_response_code(400); exit('OAuth callback was rejected.');
    }
    // Do not log the callback URL: it contains the authorization code or OAuth state.
    $callbackQuery = [];
    parse_str((string) (parse_url($callback, PHP_URL_QUERY) ?? ''), $callbackQuery);
    $callbackResult = isset($callbackQuery['code']) ? 'code'
        : (is_string($callbackQuery['error'] ?? null) ? 'error' : 'unknown');
    $callbackError = is_string($callbackQuery['error'] ?? null)
        && in_array($callbackQuery['error'], ['access_denied', 'invalid_request', 'unauthorized_client',
            'unsupported_response_type', 'invalid_scope', 'server_error', 'temporarily_unavailable'], true)
        ? $callbackQuery['error'] : 'other';
    error_log('ai-coloring-book-mcp OAuth callback issued: result=' . $callbackResult
        . ($callbackResult === 'error' ? ' error=' . $callbackError : ''));
    header('Location: ' . $callback, true, 302);
    exit;
}

function mcp_oauth_http_token(array $config): never
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        error_log('ai-coloring-book-mcp OAuth token request rejected: reason=method');
        header('Allow: POST'); http_response_code(405); exit;
    }
    $contentType = strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
    if ($contentType !== 'application/x-www-form-urlencoded') {
        error_log('ai-coloring-book-mcp OAuth token request rejected: reason=content_type');
        http_response_code(415); exit;
    }
    error_log('ai-coloring-book-mcp OAuth token request received');
    try {
        $request = mcp_oauth_http_psr_request('/oauth/token');
        $body = $request->getParsedBody();
        $authMethod = is_array($body) && isset($body['client_assertion']) ? 'private_key_jwt' : 'none';
        $grantType = is_array($body) && in_array($body['grant_type'] ?? null,
            ['authorization_code', 'refresh_token'], true) ? (string) $body['grant_type'] : 'other';
        $resource = is_array($body) ? ($body['resource'] ?? null) : null;
        $clientId = $body['client_id'] ?? null;
        $tokenRequestShape = [
            'resource=' . (!is_string($resource) ? 'missing'
                : (hash_equals($config['resource'], $resource) ? 'match' : 'mismatch')),
            'client=' . (!is_string($clientId) ? 'missing'
                : (hash_equals(MCP_OAUTH_CHATGPT_CLIENT_ID, $clientId) ? 'match' : 'mismatch')),
            'code=' . (is_string($body['code'] ?? null) && $body['code'] !== '' ? 'present' : 'missing'),
            'redirect_uri=' . (is_string($body['redirect_uri'] ?? null) && $body['redirect_uri'] !== '' ? 'present' : 'missing'),
            'verifier=' . (is_string($body['code_verifier'] ?? null) && $body['code_verifier'] !== '' ? 'present' : 'missing'),
            'secret=' . (is_string($body['client_secret'] ?? null) && $body['client_secret'] !== '' ? 'present' : 'absent'),
            'assertion=' . (is_string($body['client_assertion'] ?? null) && $body['client_assertion'] !== '' ? 'present' : 'absent'),
        ];
        error_log('ai-coloring-book-mcp OAuth token request parsed: method=' . $authMethod . ' grant=' . $grantType
            . ' ' . implode(' ', $tokenRequestShape));
        if (!is_string($clientId) || !hash_equals(MCP_OAUTH_CHATGPT_CLIENT_ID, $clientId)) {
            throw OAuthServerException::invalidClient($request);
        }
        $client = mcp_oauth_http_chatgpt_client($clientId);
        if ($client === null) throw OAuthServerException::invalidClient($request);
        [$server, $repositories] = mcp_oauth_http_server($client);
        $response = $repositories->respondToTokenRequest($server, $request, new Response());
        error_log('ai-coloring-book-mcp OAuth token response: status=' . $response->getStatusCode());
        http_response_code($response->getStatusCode());
        foreach ($response->getHeaders() as $name => $values) header($name . ': ' . implode(', ', $values));
        echo (string) $response->getBody();
        exit;
    } catch (OAuthServerException $error) {
        $errorType = preg_replace('/[^a-z0-9_]/i', '', $error->getErrorType()) ?: 'oauth_error';
        error_log('ai-coloring-book-mcp OAuth token rejected: type=' . $errorType
            . ' status=' . $error->getHttpStatusCode());
        http_response_code($error->getHttpStatusCode());
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('Pragma: no-cache');
        echo json_encode($error->getPayload(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $error) {
        error_log('ai-coloring-book-mcp OAuth token failure: class=' . get_class($error));
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode(['error' => 'server_error']);
        exit;
    }
}
