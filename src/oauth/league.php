<?php

declare(strict_types=1);

namespace AiColoringBookMcp\OAuth;

use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use PDO;
use PDOException;
use RuntimeException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

require_once __DIR__ . '/store.php';

final class McpOAuthClientEntity implements ClientEntityInterface
{
    /** @param list<string> $redirectUris */
    public function __construct(
        private string $identifier,
        private string $name,
        private array $redirectUris,
    ) {
        if ($identifier === '' || $name === '' || $redirectUris === []) {
            throw new RuntimeException('OAuth client metadata is incomplete.');
        }
    }

    public function getIdentifier(): string { return $this->identifier; }
    public function getName(): string { return $this->name; }
    public function getRedirectUri(): string|array { return $this->redirectUris; }
    public function isConfidential(): bool { return false; }
}

final class McpOAuthScopeEntity implements ScopeEntityInterface
{
    public function __construct(private string $identifier) {}
    public function getIdentifier(): string { return $this->identifier; }
    public function jsonSerialize(): string { return $this->identifier; }
}

final class McpOAuthUserEntity implements UserEntityInterface
{
    public function __construct(private string $identifier) {}
    public function getIdentifier(): string { return $this->identifier; }
}

final class McpOAuthAuthCodeEntity implements AuthCodeEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use AuthCodeTrait;
}

final class McpOAuthRefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;
}

final class McpOAuthAccessTokenEntity implements AccessTokenEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;

    private CryptKeyInterface $privateKey;
    private string $issuer;
    private string $resource;
    private string $keyId;
    private string $grantId;

    public function configureClaims(string $issuer, string $resource, string $keyId, string $grantId): void
    {
        $this->issuer = $issuer;
        $this->resource = $resource;
        $this->keyId = $keyId;
        $this->grantId = $grantId;
    }

    public function getGrantId(): string { return $this->grantId; }
    public function setPrivateKey(CryptKeyInterface $privateKey): void { $this->privateKey = $privateKey; }

    public function toString(): string
    {
        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->privateKey->getKeyContents()),
            InMemory::plainText('unused'),
        );
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $scopes = array_map(static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(), $this->getScopes());
        return $configuration->builder()
            ->withHeader('kid', $this->keyId)
            ->issuedBy($this->issuer)
            ->permittedFor($this->resource)
            ->identifiedBy($this->getIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('scope', implode(' ', $scopes))
            ->withClaim('grant_id', $this->grantId)
            ->getToken($configuration->signer(), $configuration->signingKey())
            ->toString();
    }
}

/** League enables plain PKCE by default; this adapter rejects it before authorization processing. */
final class McpOAuthS256AuthCodeGrant extends AuthCodeGrant
{
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $query = $request->getQueryParams();
        if (($query['code_challenge_method'] ?? null) !== 'S256'
            || !is_string($query['code_challenge'] ?? null)
            || preg_match('/^[A-Za-z0-9_-]{43}$/D', $query['code_challenge']) !== 1) {
            throw OAuthServerException::invalidRequest('code_challenge_method', 'Only S256 PKCE is supported.');
        }
        return parent::validateAuthorizationRequest($request);
    }
}

/**
 * SQLite-backed League repositories. An OAuth request handler must call beginTokenRequest() before
 * the League token grant and finishTokenRequest() after it, so consuming the old credential and
 * persisting its replacement form one BEGIN IMMEDIATE transaction.
 */
final class McpOAuthRepositories implements
    ClientRepositoryInterface,
    AccessTokenRepositoryInterface,
    AuthCodeRepositoryInterface,
    RefreshTokenRepositoryInterface,
    ScopeRepositoryInterface,
    UserRepositoryInterface
{
    /** @var array{account_id:string,grant_id:string,client_id:string,resource:string,scopes:list<string>}|null */
    private ?array $grantContext = null;
    /** @var array{account_id:string,grant_id:string,client_id:string,resource:string,family_id:string,scopes:list<string>,token_id:string,access_token_id:string}|null */
    private ?array $oldRefreshContext = null;
    private ?string $pendingOldRefreshTokenId = null;
    private bool $refreshReplayDetected = false;
    private bool $tokenTransactionActive = false;

    public function __construct(
        private PDO $pdo,
        private McpOAuthClientEntity $client,
        private string $issuer,
        private string $resource,
        private string $keyId,
    ) {}

    /** Must be called only after the existing-account login and explicit consent checks pass. */
    public function setAuthorizationContext(string $accountId, string $grantId, string $codeChallenge,
        string $challengeMethod = 'S256'): void
    {
        if (!mcp_account_id_valid($accountId) || preg_match('/^[A-Za-z0-9_-]{16,128}$/D', $grantId) !== 1
            || preg_match('/^[A-Za-z0-9_-]{43}$/D', $codeChallenge) !== 1 || $challengeMethod !== 'S256') {
            throw new RuntimeException('The OAuth authorization context is invalid.');
        }
        $query = $this->pdo->prepare('SELECT g.grant_id,g.account_id,g.client_id,g.resource,g.scopes,
                g.revoked_at
            FROM mcp_oauth_grants g
            WHERE g.grant_id=:grant_id AND g.account_id=:account_id');
        $query->execute(['grant_id' => $grantId, 'account_id' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        $scopes = is_array($row) ? mcp_oauth_store_parse_scopes((string) $row['scopes']) : [];
        if (!is_array($row) || $row['revoked_at'] !== null
            || (string) $row['client_id'] !== $this->client->getIdentifier()
            || (string) $row['resource'] !== $this->resource || $scopes === []) {
            throw new RuntimeException('The signed-in account or consent grant is not eligible for OAuth.');
        }
        $this->grantContext = [
            'account_id' => (string) $row['account_id'], 'grant_id' => (string) $row['grant_id'],
            'client_id' => (string) $row['client_id'], 'resource' => (string) $row['resource'],
            'scopes' => $scopes,
        ];
        $this->authorizationCodeChallenge = $codeChallenge;
    }

    private string $authorizationCodeChallenge = '';

    public function beginTokenRequest(): void
    {
        if ($this->tokenTransactionActive) throw new RuntimeException('OAuth token request transaction is already active.');
        mcp_oauth_store_begin($this->pdo);
        $this->tokenTransactionActive = true;
        $this->refreshReplayDetected = false;
        $this->pendingOldRefreshTokenId = null;
        $this->oldRefreshContext = null;
    }

    /** Commit successful exchanges and durable replay-family revocations; roll back all other errors. */
    public function finishTokenRequest(bool $success): void
    {
        if (!$this->tokenTransactionActive) throw new RuntimeException('OAuth token request transaction is not active.');
        try {
            if ($success || $this->refreshReplayDetected) $this->pdo->exec('COMMIT');
            else mcp_oauth_store_rollback($this->pdo);
        } finally {
            $this->tokenTransactionActive = false;
            $this->grantContext = null;
            $this->oldRefreshContext = null;
            $this->pendingOldRefreshTokenId = null;
            $this->authorizationCodeChallenge = '';
        }
    }

    public function refreshReplayDetected(): bool { return $this->refreshReplayDetected; }

    /** Require the single protected resource before accepting an authorization request. */
    public function assertAuthorizationResource(ServerRequestInterface $request): void
    {
        $resource = $request->getQueryParams()['resource'] ?? null;
        if (!is_string($resource) || !hash_equals($this->resource, $resource)) {
            throw OAuthServerException::invalidRequest('resource', 'The MCP resource must match exactly.');
        }
    }

    /** Require the same resource on token exchange/refresh; never silently issue an unbound token. */
    public function assertTokenResource(ServerRequestInterface $request): void
    {
        $body = $request->getParsedBody();
        $resource = is_array($body) ? ($body['resource'] ?? null) : null;
        if (!is_string($resource) || !hash_equals($this->resource, $resource)) {
            throw OAuthServerException::invalidRequest('resource', 'The MCP resource must match exactly.');
        }
    }

    /** Keep each successful League token grant in one SQLite transaction, including refresh rotation. */
    public function respondToTokenRequest(AuthorizationServer $server, ServerRequestInterface $request,
        ResponseInterface $response): ResponseInterface
    {
        $this->assertTokenResource($request);
        $this->beginTokenRequest();
        try {
            $result = $server->respondToAccessTokenRequest($request, $response);
            $this->finishTokenRequest(true);
            return $result;
        } catch (Throwable $error) {
            if ($this->tokenTransactionActive) $this->finishTokenRequest(false);
            throw $error;
        }
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return hash_equals($this->client->getIdentifier(), $clientIdentifier) ? $this->client : null;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return hash_equals($this->client->getIdentifier(), $clientIdentifier)
            && $clientSecret === null
            && in_array($grantType, ['authorization_code', 'refresh_token'], true);
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $accountIdentifier = null): AccessTokenEntityInterface
    {
        if (!$clientEntity instanceof McpOAuthClientEntity || $accountIdentifier === null) {
            throw new RuntimeException('OAuth access tokens require the configured public client and an existing user.');
        }
        $context = $this->grantContext ?? $this->oldRefreshContext;
        if ($context === null || (string) $context['account_id'] !== $accountIdentifier
            || $context['client_id'] !== $clientEntity->getIdentifier()) {
            throw new RuntimeException('OAuth access token has no validated grant context.');
        }
        $token = new McpOAuthAccessTokenEntity();
        $token->setClient($clientEntity);
        $token->setUserIdentifier($accountIdentifier);
        foreach ($scopes as $scope) $token->addScope($scope);
        $token->configureClaims($this->issuer, $this->resource, $this->keyId, $context['grant_id']);
        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        if (!$accessTokenEntity instanceof McpOAuthAccessTokenEntity) throw new RuntimeException('Unexpected OAuth token entity.');
        $context = $this->grantContext ?? $this->oldRefreshContext;
        if ($context === null || (string) $context['account_id'] !== (string) $accessTokenEntity->getUserIdentifier()
            || $accessTokenEntity->getClient()->getIdentifier() !== $context['client_id']
            || $accessTokenEntity->getGrantId() !== $context['grant_id']) {
            throw new RuntimeException('Access-token persistence does not match its validated grant.');
        }
        $scopes = $this->scopeIdentifiers($accessTokenEntity->getScopes());
        if ($scopes === [] || array_diff($scopes, $context['scopes']) !== []) {
            throw new RuntimeException('OAuth access token exceeds the consented scopes.');
        }
        try {
            $insert = $this->pdo->prepare('INSERT INTO mcp_oauth_access_tokens
                (token_id,account_id,grant_id,client_id,resource,scopes,expires_at)
                VALUES (:token_id,:account_id,:grant_id,:client_id,:resource,:scopes,:expires_at)');
            $insert->execute([
                'token_id' => $accessTokenEntity->getIdentifier(), 'account_id' => $context['account_id'],
                'grant_id' => $context['grant_id'], 'client_id' => $context['client_id'],
                'resource' => $context['resource'], 'scopes' => implode(' ', $scopes),
                'expires_at' => $accessTokenEntity->getExpiryDateTime()->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
            ]);
        } catch (PDOException $error) {
            if (str_contains(strtolower($error->getMessage()), 'unique')) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }
            throw $error;
        }
    }

    public function revokeAccessToken(string $tokenId): void
    {
        if ($this->oldRefreshContext === null
            || !hash_equals($this->oldRefreshContext['access_token_id'], $tokenId)) {
            throw new RuntimeException('Access-token retirement has no matching refresh context.');
        }
        // League invokes this hook during normal refresh. Retire the predecessor at its
        // ORIGINAL expiry instead: parallel tool requests can still carry its valid JWT.
        // Do not extend its lifetime or undo any existing revocation. Refresh-token
        // rotation remains single-use; replay-family and explicit grant revocation
        // separately revoke ALL associated access tokens immediately.
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $statement = $this->pdo->prepare('SELECT revoked_at,expires_at FROM mcp_oauth_access_tokens WHERE token_id=:token_id');
        $statement->execute(['token_id' => $tokenId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return !is_array($row) || $row['revoked_at'] !== null || (string) $row['expires_at'] <= gmdate('Y-m-d H:i:s');
    }

    public function getNewAuthCode(): AuthCodeEntityInterface { return new McpOAuthAuthCodeEntity(); }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $context = $this->grantContext;
        if ($context === null || (string) $context['account_id'] !== (string) $authCodeEntity->getUserIdentifier()
            || $authCodeEntity->getClient()->getIdentifier() !== $context['client_id']
            || $authCodeEntity->getRedirectUri() === null
            || !in_array($authCodeEntity->getRedirectUri(), (array) $this->client->getRedirectUri(), true)
            || $this->authorizationCodeChallenge === '') {
            throw new RuntimeException('Authorization code does not match the validated consent context.');
        }
        $scopes = $this->scopeIdentifiers($authCodeEntity->getScopes());
        if ($scopes === [] || array_diff($scopes, $context['scopes']) !== []) {
            throw new RuntimeException('Authorization code exceeds the consented scopes.');
        }
        try {
            $insert = $this->pdo->prepare('INSERT INTO mcp_oauth_authorization_codes
                (code_id,account_id,grant_id,client_id,resource,redirect_uri,scopes,code_challenge,
                    code_challenge_method,expires_at)
                VALUES (:code_id,:account_id,:grant_id,:client_id,:resource,:redirect_uri,:scopes,
                    :challenge,\'s256\',:expires_at)');
            $insert->execute([
                'code_id' => $authCodeEntity->getIdentifier(), 'account_id' => $context['account_id'],
                'grant_id' => $context['grant_id'], 'client_id' => $context['client_id'],
                'resource' => $context['resource'], 'redirect_uri' => $authCodeEntity->getRedirectUri(),
                'scopes' => implode(' ', $scopes), 'challenge' => $this->authorizationCodeChallenge,
                'expires_at' => $authCodeEntity->getExpiryDateTime()->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
            ]);
        } catch (PDOException $error) {
            if (str_contains(strtolower($error->getMessage()), 'unique')) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }
            throw $error;
        }
    }

    public function revokeAuthCode(string $codeId): void
    {
        $statement = $this->pdo->prepare('UPDATE mcp_oauth_authorization_codes SET revoked_at=CURRENT_TIMESTAMP
            WHERE code_id=:code_id AND revoked_at IS NULL');
        $statement->execute(['code_id' => $codeId]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $statement = $this->pdo->prepare('SELECT c.revoked_at,c.expires_at,c.client_id,c.resource,c.scopes,
                c.account_id,c.grant_id,g.revoked_at AS grant_revoked_at
            FROM mcp_oauth_authorization_codes c
            JOIN mcp_oauth_grants g ON g.grant_id=c.grant_id AND g.account_id=c.account_id WHERE c.code_id=:code_id');
        $statement->execute(['code_id' => $codeId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row) || $row['revoked_at'] !== null || $row['grant_revoked_at'] !== null
            || (string) $row['expires_at'] <= gmdate('Y-m-d H:i:s')
            || (string) $row['client_id'] !== $this->client->getIdentifier()
            || (string) $row['resource'] !== $this->resource
           ) return true;
        return false;
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface { return new McpOAuthRefreshTokenEntity(); }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $access = $refreshTokenEntity->getAccessToken();
        if (!$access instanceof McpOAuthAccessTokenEntity) throw new RuntimeException('Unexpected OAuth access token entity.');
        $context = $this->grantContext ?? $this->oldRefreshContext;
        if ($context === null || (string) $context['account_id'] !== (string) $access->getUserIdentifier()
            || $context['grant_id'] !== $access->getGrantId()) throw new RuntimeException('Refresh token has no validated grant context.');
        $familyId = $context['family_id'] ?? bin2hex(random_bytes(24));
        try {
            $insert = $this->pdo->prepare('INSERT INTO mcp_oauth_refresh_tokens
                (token_id,account_id,grant_id,client_id,resource,family_id,access_token_id,scopes,
                    expires_at)
                VALUES (:token_id,:account_id,:grant_id,:client_id,:resource,:family_id,:access_token_id,
                    :scopes,:expires_at)');
            $insert->execute([
                'token_id' => $refreshTokenEntity->getIdentifier(), 'account_id' => $context['account_id'],
                'grant_id' => $context['grant_id'], 'client_id' => $context['client_id'],
                'resource' => $context['resource'], 'family_id' => $familyId,
                'access_token_id' => $access->getIdentifier(),
                'scopes' => implode(' ', $this->scopeIdentifiers($access->getScopes())),
                'expires_at' => $refreshTokenEntity->getExpiryDateTime()->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
            ]);
        } catch (PDOException $error) {
            if (str_contains(strtolower($error->getMessage()), 'unique')) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }
            throw $error;
        }
        if ($this->pendingOldRefreshTokenId !== null) {
            $replace = $this->pdo->prepare('UPDATE mcp_oauth_refresh_tokens SET replaced_by=:replacement,
                    revoked_at=CURRENT_TIMESTAMP
                WHERE token_id=:old_id AND revoked_at IS NULL AND replaced_by IS NULL');
            $replace->execute(['replacement' => $refreshTokenEntity->getIdentifier(), 'old_id' => $this->pendingOldRefreshTokenId]);
            if ($replace->rowCount() !== 1) throw new RuntimeException('Refresh-token replacement was not one-time.');
        }
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        // League calls this before it persists the new token. Defer the write-once predecessor link
        // until persistNewRefreshToken knows the replacement identifier; both are inside one txn.
        if ($this->oldRefreshContext === null || $this->oldRefreshContext['token_id'] !== $tokenId) {
            throw new RuntimeException('Refresh revocation has no matching active token context.');
        }
        $this->pendingOldRefreshTokenId = $tokenId;
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $statement = $this->pdo->prepare('SELECT r.token_id,r.account_id,r.grant_id,r.client_id,r.resource,
                r.family_id,r.access_token_id,r.scopes,r.expires_at,r.revoked_at,r.replaced_by,
                g.revoked_at AS grant_revoked_at,g.resource AS grant_resource,g.scopes AS grant_scopes
            FROM mcp_oauth_refresh_tokens r
            JOIN mcp_oauth_grants g ON g.grant_id=r.grant_id AND g.account_id=r.account_id WHERE r.token_id=:token_id');
        $statement->execute(['token_id' => $tokenId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) return true;
        if ($row['replaced_by'] !== null) {
            $this->refreshReplayDetected = true;
            $this->revokeFamilyInsideTransaction((string) $row['family_id']);
            return true;
        }
        if ($row['revoked_at'] !== null || $row['grant_revoked_at'] !== null
            || (string) $row['expires_at'] <= gmdate('Y-m-d H:i:s')
            || !hash_equals((string) $row['resource'], (string) $row['grant_resource'])
            || !hash_equals((string) $row['client_id'], $this->client->getIdentifier())
            || !hash_equals((string) $row['resource'], $this->resource)) return true;
        $scopes = mcp_oauth_store_parse_scopes((string) $row['scopes']);
        $grantScopes = mcp_oauth_store_parse_scopes((string) $row['grant_scopes']);
        if ($scopes === [] || array_diff($scopes, $grantScopes) !== []) return true;
        $this->oldRefreshContext = [
            'account_id' => (string) $row['account_id'], 'grant_id' => (string) $row['grant_id'],
            'client_id' => (string) $row['client_id'], 'resource' => (string) $row['resource'],
            'family_id' => (string) $row['family_id'], 'scopes' => $scopes,
            'token_id' => (string) $row['token_id'],
            'access_token_id' => (string) $row['access_token_id'],
        ];
        $this->grantContext = $this->oldRefreshContext;
        return false;
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return in_array($identifier, ['books:read', 'books:write', 'books:export'], true)
            ? new McpOAuthScopeEntity($identifier) : null;
    }

    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity,
        ?string $accountIdentifier = null, ?string $authCodeId = null): array
    {
        if ($clientEntity->getIdentifier() !== $this->client->getIdentifier()) return [];
        $identifiers = $this->scopeIdentifiers($scopes);
        if (!in_array('books:read', $identifiers, true)) return [];
        if ($authCodeId === null) {
            $context = $this->grantContext ?? $this->oldRefreshContext;
            if ($context !== null && array_diff($identifiers, $context['scopes']) !== []) return [];
            return $scopes;
        }
        $query = $this->pdo->prepare('SELECT c.account_id,c.grant_id,c.client_id,c.resource,c.scopes,
                g.revoked_at AS grant_revoked_at
            FROM mcp_oauth_authorization_codes c
            JOIN mcp_oauth_grants g ON g.grant_id=c.grant_id AND g.account_id=c.account_id WHERE c.code_id=:code_id AND c.revoked_at IS NULL');
        $query->execute(['code_id' => $authCodeId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row) || $row['grant_revoked_at'] !== null
            || (string) $row['client_id'] !== $this->client->getIdentifier()
            || (string) $row['resource'] !== $this->resource
            || ($accountIdentifier !== null && (string) $row['account_id'] !== $accountIdentifier)) return [];
        $consentedScopes = mcp_oauth_store_parse_scopes((string) $row['scopes']);
        if (array_diff($identifiers, $consentedScopes) !== []) return [];
        $this->grantContext = [
            'account_id' => (string) $row['account_id'], 'grant_id' => (string) $row['grant_id'],
            'client_id' => (string) $row['client_id'], 'resource' => (string) $row['resource'],
            'scopes' => $consentedScopes,
        ];
        return $scopes;
    }

    public function getUserEntityByUserCredentials(string $username, string $password, string $grantType,
        ClientEntityInterface $clientEntity): ?UserEntityInterface
    {
        // OAuth never accepts account passwords; login happens through the existing website session.
        return null;
    }

    /** @param list<ScopeEntityInterface> $scopes @return list<string> */
    private function scopeIdentifiers(array $scopes): array
    {
        $identifiers = [];
        foreach ($scopes as $scope) {
            if (!$scope instanceof ScopeEntityInterface || $this->getScopeEntityByIdentifier($scope->getIdentifier()) === null) {
                throw new RuntimeException('OAuth scope is not supported.');
            }
            $identifiers[] = $scope->getIdentifier();
        }
        return count($identifiers) === count(array_unique($identifiers)) ? $identifiers : [];
    }

    private function revokeFamilyInsideTransaction(string $familyId): void
    {
        $tokens = $this->pdo->prepare('UPDATE mcp_oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
            WHERE family_id=:family_id AND revoked_at IS NULL');
        $tokens->execute(['family_id' => $familyId]);
        $access = $this->pdo->prepare('UPDATE mcp_oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
            WHERE token_id IN (SELECT access_token_id FROM mcp_oauth_refresh_tokens WHERE family_id=:family_id)
                AND revoked_at IS NULL');
        $access->execute(['family_id' => $familyId]);
    }
}
