<?php

declare(strict_types=1);


/**
 * Validate the durable authorization state behind a cryptographically valid OAuth access token.
 * Call only after validating JWT signature, issuer, resource audience, exp/nbf and algorithm.
 * Every check is repeated against SQLite so disconnects and account-security changes take effect
 * immediately rather than waiting for the JWT to expire.
 *
 * @param list<string> $requiredScopes
 * @return array{account_id:string,token_id:string,grant_id:string,client_id:string,resource:string,scopes:list<string>}|null
 */
function mcp_oauth_store_validate_access_token(string $tokenId, string $accountId, string $resource,
    array $requiredScopes, ?PDO $pdo = null): ?array
{
    if (!mcp_account_id_valid($accountId) || preg_match('/^[A-Za-z0-9_-]{16,128}$/D', $tokenId) !== 1
        || $resource === '' || count(array_filter($requiredScopes, 'is_string')) !== count($requiredScopes)) {
        return null;
    }
    $pdo ??= mcp_db();
    $query = $pdo->prepare('SELECT a.token_id,a.account_id,a.grant_id,a.client_id,a.resource,a.scopes,
            a.expires_at,a.revoked_at,
            g.revoked_at AS grant_revoked_at,g.resource AS grant_resource,g.scopes AS grant_scopes
        FROM mcp_oauth_access_tokens a
        INNER JOIN mcp_oauth_grants g ON g.grant_id=a.grant_id AND g.account_id=a.account_id
        WHERE a.token_id=:token_id AND a.account_id=:account_id');
    $query->execute(['token_id' => $tokenId, 'account_id' => $accountId]);
    $row = $query->fetch(PDO::FETCH_ASSOC);
    $now = gmdate('Y-m-d H:i:s');
    if (!is_array($row) || $row['revoked_at'] !== null || $row['grant_revoked_at'] !== null
        || (string) $row['expires_at'] <= $now
        || !hash_equals((string) $row['resource'], $resource)
        || !hash_equals((string) $row['grant_resource'], $resource)) {
        return null;
    }
    $scopes = mcp_oauth_store_parse_scopes((string) $row['scopes']);
    $grantScopes = mcp_oauth_store_parse_scopes((string) $row['grant_scopes']);
    if ($scopes === [] || array_diff($scopes, $grantScopes) !== []
        || array_diff($requiredScopes, $scopes) !== []) {
        return null;
    }
    return [
        'account_id' => (string) $row['account_id'],
        'token_id' => (string) $row['token_id'],
        'grant_id' => (string) $row['grant_id'],
        'client_id' => (string) $row['client_id'],
        'resource' => (string) $row['resource'],
        'scopes' => $scopes,
    ];
}

/** Revoke one user's grant and all tokens issued under it, idempotently. */
function mcp_oauth_store_revoke_grant(string $accountId, string $grantId, ?PDO $pdo = null): bool
{
    if (!mcp_account_id_valid($accountId) || preg_match('/^[A-Za-z0-9_-]{16,128}$/D', $grantId) !== 1) return false;
    $pdo ??= mcp_db();
    mcp_oauth_store_begin($pdo);
    try {
        $grant = $pdo->prepare('UPDATE mcp_oauth_grants SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
            WHERE grant_id=:grant_id AND account_id=:account_id AND revoked_at IS NULL');
        $grant->execute(['grant_id' => $grantId, 'account_id' => $accountId]);
        $changed = $grant->rowCount() === 1;
        $access = $pdo->prepare('UPDATE mcp_oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
            WHERE grant_id=:grant_id AND account_id=:account_id AND revoked_at IS NULL');
        $access->execute(['grant_id' => $grantId, 'account_id' => $accountId]);
        $refresh = $pdo->prepare('UPDATE mcp_oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
            WHERE grant_id=:grant_id AND account_id=:account_id AND revoked_at IS NULL');
        $refresh->execute(['grant_id' => $grantId, 'account_id' => $accountId]);
        $pdo->exec('COMMIT');
        return $changed;
    } catch (Throwable $error) {
        mcp_oauth_store_rollback($pdo);
        throw $error;
    }
}

/**
 * Revoke a refresh family. A caller invokes this when an already-rotated token is replayed.
 */
function mcp_oauth_store_revoke_refresh_family(string $familyId, ?PDO $pdo = null): bool
{
    if (preg_match('/^[A-Za-z0-9_-]{16,128}$/D', $familyId) !== 1) return false;
    $pdo ??= mcp_db();
    mcp_oauth_store_begin($pdo);
    try {
        $tokens = $pdo->prepare('UPDATE mcp_oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
            WHERE family_id=:family_id AND revoked_at IS NULL');
        $tokens->execute(['family_id' => $familyId]);
        $access = $pdo->prepare('UPDATE mcp_oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
            WHERE token_id IN (SELECT access_token_id FROM mcp_oauth_refresh_tokens WHERE family_id=:family_id)
                AND revoked_at IS NULL');
        $access->execute(['family_id' => $familyId]);
        $pdo->exec('COMMIT');
        return $tokens->rowCount() > 0;
    } catch (Throwable $error) {
        mcp_oauth_store_rollback($pdo);
        throw $error;
    }
}

/**
 * Atomically validate and consume an authorization code after the OAuth library has validated
 * its signed code envelope. PKCE is independently checked here as a durable one-time guard.
 * Returns the existing-account grant context exactly once.
 *
 * @return array{code_id:string,account_id:string,grant_id:string,client_id:string,resource:string,scopes:list<string>}|null
 */
function mcp_oauth_store_consume_authorization_code(string $codeId, string $clientId, string $redirectUri,
    string $resource, string $verifier, ?PDO $pdo = null): ?array
{
    if (preg_match('/^[A-Za-z0-9_-]{16,128}$/D', $codeId) !== 1 || $clientId === ''
        || $redirectUri === '' || $resource === ''
        || preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $verifier) !== 1) return null;
    $pdo ??= mcp_db();
    mcp_oauth_store_begin($pdo);
    try {
        $query = $pdo->prepare('SELECT c.code_id,c.account_id,c.grant_id,c.client_id,c.resource,c.redirect_uri,
                c.scopes,c.code_challenge,c.code_challenge_method,c.expires_at,c.revoked_at,
                g.revoked_at AS grant_revoked_at,g.resource AS grant_resource,g.scopes AS grant_scopes
            FROM mcp_oauth_authorization_codes c
            INNER JOIN mcp_oauth_grants g ON g.grant_id=c.grant_id AND g.account_id=c.account_id
            WHERE c.code_id=:code_id');
        $query->execute(['code_id' => $codeId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        $now = gmdate('Y-m-d H:i:s');
        $scopes = is_array($row) ? mcp_oauth_store_parse_scopes((string) $row['scopes']) : [];
        $grantScopes = is_array($row) ? mcp_oauth_store_parse_scopes((string) $row['grant_scopes']) : [];
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        if (!is_array($row) || $row['revoked_at'] !== null || $row['grant_revoked_at'] !== null
            || (string) $row['expires_at'] <= $now
            || !hash_equals((string) $row['client_id'], $clientId)
            || !hash_equals((string) $row['redirect_uri'], $redirectUri)
            || !hash_equals((string) $row['resource'], $resource)
            || !hash_equals((string) $row['grant_resource'], $resource)
            || (string) $row['code_challenge_method'] !== 's256'
            || !hash_equals((string) $row['code_challenge'], $challenge)
            || $scopes === [] || array_diff($scopes, $grantScopes) !== []) {
            $pdo->exec('ROLLBACK');
            return null;
        }
        $consume = $pdo->prepare('UPDATE mcp_oauth_authorization_codes SET revoked_at=CURRENT_TIMESTAMP
            WHERE code_id=:code_id AND revoked_at IS NULL AND expires_at>:now');
        $consume->execute(['code_id' => $codeId, 'now' => $now]);
        if ($consume->rowCount() !== 1) {
            $pdo->exec('ROLLBACK');
            return null;
        }
        $pdo->exec('COMMIT');
        return [
            'code_id' => (string) $row['code_id'],
            'account_id' => (string) $row['account_id'],
            'grant_id' => (string) $row['grant_id'],
            'client_id' => (string) $row['client_id'],
            'resource' => (string) $row['resource'],
            'scopes' => $scopes,
        ];
    } catch (Throwable $error) {
        mcp_oauth_store_rollback($pdo);
        throw $error;
    }
}

/**
 * Atomically rotate a refresh token and persist its replacement access token. The caller creates
 * and signs the JWT first, then passes its immutable database fields here; nothing is returned on
 * invalid/replayed credentials. A detected replay revokes the whole family and its access tokens.
 *
 * @param array{token_id:string,expires_at:string} $newAccessToken
 * @return array{account_id:string,grant_id:string,family_id:string,client_id:string,resource:string,scopes:list<string>}|null
 */
function mcp_oauth_store_rotate_refresh_token(string $oldTokenId, string $newRefreshTokenId,
    array $newAccessToken, string $newRefreshExpiresAt, ?PDO $pdo = null): ?array
{
    if (preg_match('/^[A-Za-z0-9_-]{16,128}$/D', $oldTokenId) !== 1
        || preg_match('/^[A-Za-z0-9_-]{16,128}$/D', $newRefreshTokenId) !== 1
        || preg_match('/^[A-Za-z0-9_-]{16,128}$/D', (string) ($newAccessToken['token_id'] ?? '')) !== 1
        || !mcp_oauth_store_valid_timestamp((string) ($newAccessToken['expires_at'] ?? ''))
        || !mcp_oauth_store_valid_timestamp($newRefreshExpiresAt)) return null;
    $pdo ??= mcp_db();
    mcp_oauth_store_begin($pdo);
    try {
        $query = $pdo->prepare('SELECT r.*,g.revoked_at AS grant_revoked_at,g.resource AS grant_resource,
                g.scopes AS grant_scopes
            FROM mcp_oauth_refresh_tokens r
            INNER JOIN mcp_oauth_grants g ON g.grant_id=r.grant_id AND g.account_id=r.account_id
            WHERE r.token_id=:token_id');
        $query->execute(['token_id' => $oldTokenId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        $now = gmdate('Y-m-d H:i:s');
        if (!is_array($row)) {
            $pdo->exec('ROLLBACK');
            return null;
        }
        if ($row['replaced_by'] !== null) {
            $family = (string) $row['family_id'];
            $revoke = $pdo->prepare('UPDATE mcp_oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
                WHERE family_id=:family_id AND revoked_at IS NULL');
            $revoke->execute(['family_id' => $family]);
            $access = $pdo->prepare('UPDATE mcp_oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP)
                WHERE token_id IN (SELECT access_token_id FROM mcp_oauth_refresh_tokens WHERE family_id=:family_id)
                    AND revoked_at IS NULL');
            $access->execute(['family_id' => $family]);
            $pdo->exec('COMMIT');
            return null;
        }
        $scopes = mcp_oauth_store_parse_scopes((string) $row['scopes']);
        $grantScopes = mcp_oauth_store_parse_scopes((string) $row['grant_scopes']);
        $newAccessExpiry = (string) $newAccessToken['expires_at'];
        if ($row['revoked_at'] !== null || $row['grant_revoked_at'] !== null
            || (string) $row['expires_at'] <= $now
            || !hash_equals((string) $row['resource'], (string) $row['grant_resource'])
            || $scopes === [] || array_diff($scopes, $grantScopes) !== []
            || $newAccessExpiry <= $now || $newRefreshExpiresAt <= $newAccessExpiry
            || $newRefreshTokenId === $oldTokenId
            || $newAccessToken['token_id'] === (string) $row['access_token_id']) {
            $pdo->exec('ROLLBACK');
            return null;
        }
        $accessInsert = $pdo->prepare('INSERT INTO mcp_oauth_access_tokens
            (token_id,account_id,grant_id,client_id,resource,scopes,expires_at)
            VALUES (:token_id,:account_id,:grant_id,:client_id,:resource,:scopes,:expires_at)');
        $accessInsert->execute([
            'token_id' => $newAccessToken['token_id'], 'account_id' => (string) $row['account_id'],
            'grant_id' => (string) $row['grant_id'], 'client_id' => (string) $row['client_id'],
            'resource' => (string) $row['resource'], 'scopes' => implode(' ', $scopes),
            'expires_at' => $newAccessExpiry,
        ]);
        $refreshInsert = $pdo->prepare('INSERT INTO mcp_oauth_refresh_tokens
            (token_id,account_id,grant_id,client_id,resource,family_id,access_token_id,scopes,
                expires_at)
            VALUES (:token_id,:account_id,:grant_id,:client_id,:resource,:family_id,:access_token_id,
                :scopes,:expires_at)');
        $refreshInsert->execute([
            'token_id' => $newRefreshTokenId, 'account_id' => (string) $row['account_id'],
            'grant_id' => (string) $row['grant_id'], 'client_id' => (string) $row['client_id'],
            'resource' => (string) $row['resource'], 'family_id' => (string) $row['family_id'],
            'access_token_id' => $newAccessToken['token_id'], 'scopes' => implode(' ', $scopes),
            'expires_at' => $newRefreshExpiresAt,
        ]);
        $consume = $pdo->prepare('UPDATE mcp_oauth_refresh_tokens SET replaced_by=:replacement,
                revoked_at=CURRENT_TIMESTAMP
            WHERE token_id=:token_id AND replaced_by IS NULL AND revoked_at IS NULL');
        $consume->execute(['replacement' => $newRefreshTokenId, 'token_id' => $oldTokenId]);
        if ($consume->rowCount() !== 1) {
            throw new RuntimeException('Refresh-token rotation lost its one-time update race.');
        }
        $pdo->exec('COMMIT');
        return [
            'account_id' => (string) $row['account_id'], 'grant_id' => (string) $row['grant_id'],
            'family_id' => (string) $row['family_id'], 'client_id' => (string) $row['client_id'],
            'resource' => (string) $row['resource'], 'scopes' => $scopes,
        ];
    } catch (Throwable $error) {
        mcp_oauth_store_rollback($pdo);
        throw $error;
    }
}

/** @return list<string> */
function mcp_oauth_store_parse_scopes(string $value): array
{
    if ($value === '' || preg_match('/^[a-z:]+(?: [a-z:]+)*$/D', $value) !== 1) return [];
    $scopes = explode(' ', $value);
    return count($scopes) === count(array_unique($scopes)) ? $scopes : [];
}

function mcp_oauth_store_valid_timestamp(string $value): bool
{
    $date = DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', $value, new DateTimeZone('UTC'));
    return $date instanceof DateTimeImmutable && $date->format('Y-m-d H:i:s') === $value;
}

function mcp_oauth_store_begin(PDO $pdo): void
{
    if ($pdo->inTransaction()) throw new LogicException('OAuth store transactions cannot be nested.');
    $pdo->exec('BEGIN IMMEDIATE');
}

function mcp_oauth_store_rollback(PDO $pdo): void
{
    try { $pdo->exec('ROLLBACK'); } catch (Throwable) { /* SQLite may already have rolled back. */ }
}

/**
 * Persist the validated consent request outside the PHP session. Some production request paths
 * can retain the account/CSRF session while losing an OAuth-specific session key; the durable,
 * one-use record keeps consent bound to the same account and browser session without trusting a
 * request URL or ChatGPT-provided form fields.
 *
 * @param array<string,string> $params
 */
function mcp_oauth_store_create_pending_authorization(array $params, string $accountId,
    string $sessionBinding, int $expiresAt, ?PDO $pdo = null): string
{
    if (!mcp_account_id_valid($accountId) || preg_match('/^[a-f0-9]{64}$/D', $sessionBinding) !== 1
        || $expiresAt <= time() || $expiresAt > time() + 3600 || $params === []) {
        throw new InvalidArgumentException('Pending OAuth authorization is malformed.');
    }
    $paramsJson = json_encode($params, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    if (strlen($paramsJson) > 8192) throw new InvalidArgumentException('Pending OAuth authorization is too large.');
    $pdo ??= mcp_db();
    $now = gmdate('Y-m-d H:i:s');
    $expiry = gmdate('Y-m-d H:i:s', $expiresAt);
    // Bound housekeeping work on the request path even if an attacker creates many valid-looking
    // authorization starts. Expired rows are inert and are removed in small batches.
    $pdo->exec("DELETE FROM mcp_oauth_pending_authorizations WHERE id IN (
        SELECT id FROM mcp_oauth_pending_authorizations WHERE expires_at <= " . $pdo->quote($now)
        . ' ORDER BY id LIMIT 100)');
    $requestHandle = bin2hex(random_bytes(32));
    $insert = $pdo->prepare('INSERT INTO mcp_oauth_pending_authorizations
        (request_hash,session_binding,account_id,params_json,expires_at)
        VALUES (:request_hash,:session_binding,:account_id,:params_json,:expires_at)');
    $insert->execute(['request_hash' => hash('sha256', $requestHandle),
        'session_binding' => $sessionBinding, 'account_id' => $accountId,
        'params_json' => $paramsJson, 'expires_at' => $expiry]);
    return $requestHandle;
}

/** @return array<string,string>|null */
function mcp_oauth_store_find_pending_authorization(string $requestHandle, string $sessionBinding,
    string $accountId, ?PDO $pdo = null): ?array
{
    if (preg_match('/^[a-f0-9]{64}$/D', $requestHandle) !== 1
        || preg_match('/^[a-f0-9]{64}$/D', $sessionBinding) !== 1 || !mcp_account_id_valid($accountId)) return null;
    $pdo ??= mcp_db();
    $query = $pdo->prepare('SELECT params_json FROM mcp_oauth_pending_authorizations
        WHERE request_hash=:request_hash AND session_binding=:session_binding AND account_id=:account_id
            AND consumed_at IS NULL AND expires_at>:now');
    $query->execute(['request_hash' => hash('sha256', $requestHandle),
        'session_binding' => $sessionBinding, 'account_id' => $accountId, 'now' => gmdate('Y-m-d H:i:s')]);
    $json = $query->fetchColumn();
    if (!is_string($json)) return null;
    try { $params = json_decode($json, true, flags: JSON_THROW_ON_ERROR); }
    catch (JsonException) { return null; }
    if (!is_array($params) || $params === []) return null;
    foreach ($params as $key => $value) if (!is_string($key) || !is_string($value)) return null;
    return $params;
}

/** Atomically allow one POST to decide a pending consent request. */
function mcp_oauth_store_consume_pending_authorization(string $requestHandle, string $sessionBinding,
    string $accountId, ?PDO $pdo = null): bool
{
    if (preg_match('/^[a-f0-9]{64}$/D', $requestHandle) !== 1
        || preg_match('/^[a-f0-9]{64}$/D', $sessionBinding) !== 1 || !mcp_account_id_valid($accountId)) return false;
    $pdo ??= mcp_db();
    $consume = $pdo->prepare('UPDATE mcp_oauth_pending_authorizations SET consumed_at=CURRENT_TIMESTAMP
        WHERE request_hash=:request_hash AND session_binding=:session_binding AND account_id=:account_id
            AND consumed_at IS NULL AND expires_at>:now');
    $consume->execute(['request_hash' => hash('sha256', $requestHandle),
        'session_binding' => $sessionBinding, 'account_id' => $accountId, 'now' => gmdate('Y-m-d H:i:s')]);
    return $consume->rowCount() === 1;
}
