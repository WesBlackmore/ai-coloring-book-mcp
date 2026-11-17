<?php

declare(strict_types=1);

const MCP_PAT_READ_SCOPE = 'books:read';
const MCP_PAT_WRITE_SCOPE = 'books:write';
const MCP_PAT_EXPORT_SCOPE = 'books:export';

function mcp_pat_max_days(): int
{
    $configured = (int) getenv('MCP_PAT_MAX_DAYS');
    return $configured > 0 ? min(3650, $configured) : 90;
}

/**
 * How a token secret is stored. With MCP_PAT_PEPPER set it is an HMAC, so a copied database alone cannot
 * be used to verify guessed tokens. Changing the pepper invalidates every issued token.
 */
function mcp_pat_secret_hash(string $token): string
{
    $pepper = (string) getenv('MCP_PAT_PEPPER');
    return $pepper !== '' ? hash_hmac('sha256', $token, $pepper) : hash('sha256', $token);
}

/**
 * Issue one credential for an account. The raw token is returned once and never stored or logged.
 * The READ scope is mandatory; WRITE and EXPORT are opt-in per token.
 *
 * @return array{token:string,id:string,expires_at:string}
 */
function mcp_pat_issue(string $accountId, string $label, int $days = 30, ?PDO $pdo = null,
    array $scopes = [MCP_PAT_READ_SCOPE]): array
{
    $scopes = array_values(array_unique($scopes));
    $allowed = [MCP_PAT_READ_SCOPE, MCP_PAT_WRITE_SCOPE, MCP_PAT_EXPORT_SCOPE];
    if (!in_array(MCP_PAT_READ_SCOPE, $scopes, true)
        || count(array_filter($scopes, 'is_string')) !== count($scopes)
        || array_diff($scopes, $allowed) !== []) {
        throw new InvalidArgumentException('Those MCP permissions are not available.');
    }
    $label = trim($label);
    if (!mcp_account_id_valid($accountId) || $label === '' || mb_strlen($label) > 80
        || preg_match('/[\x00-\x1F\x7F]/', $label) === 1
        || $days < 1 || $days > mcp_pat_max_days()) {
        throw new InvalidArgumentException('Choose a valid account id, a label and an expiry of 1 to '
            . mcp_pat_max_days() . ' days.');
    }
    $pdo ??= mcp_db();
    $active = $pdo->prepare('SELECT COUNT(*) FROM mcp_personal_access_tokens
        WHERE account_id = ? AND revoked_at IS NULL AND expires_at > ?');
    $active->execute([$accountId, gmdate('Y-m-d H:i:s')]);
    if ((int) $active->fetchColumn() >= 30) {
        throw new InvalidArgumentException('Revoke an unused token before creating another.');
    }

    $id = bin2hex(random_bytes(12));
    $token = 'mcp_pat_' . $id . '_' . bin2hex(random_bytes(32));
    $expiresAt = gmdate('Y-m-d H:i:s', time() + $days * 86400);
    $pdo->prepare('INSERT INTO mcp_personal_access_tokens (token_id, secret_hash, account_id, label, scopes, expires_at)
        VALUES (:token_id, :secret_hash, :account_id, :label, :scopes, :expires_at)')->execute([
        'token_id' => $id,
        'secret_hash' => mcp_pat_secret_hash($token),
        'account_id' => $accountId,
        'label' => $label,
        'scopes' => implode(' ', $scopes),
        'expires_at' => $expiresAt,
    ]);
    return ['token' => $token, 'id' => $id, 'expires_at' => $expiresAt];
}

/** @return array{account_id:string,token_id:string,scopes:list<string>}|null */
function mcp_pat_authenticate(string $authorization, ?PDO $pdo = null): ?array
{
    if (!preg_match('/^(?i:Bearer) (mcp_pat_([a-f0-9]{24})_[a-f0-9]{64})$/D', $authorization, $match)) {
        return null;
    }
    $pdo ??= mcp_db();
    $statement = $pdo->prepare('SELECT token_id, secret_hash, account_id, scopes, expires_at, revoked_at
        FROM mcp_personal_access_tokens WHERE token_id = :token_id');
    $statement->execute(['token_id' => $match[2]]);
    $row = $statement->fetch(PDO::FETCH_ASSOC);
    if (!is_array($row) || !hash_equals((string) $row['secret_hash'], mcp_pat_secret_hash($match[1]))
        || $row['revoked_at'] !== null || (string) $row['expires_at'] <= gmdate('Y-m-d H:i:s')) {
        return null;
    }
    $scopes = explode(' ', (string) $row['scopes']);
    if (!in_array(MCP_PAT_READ_SCOPE, $scopes, true)) return null;
    return ['account_id' => (string) $row['account_id'], 'token_id' => (string) $row['token_id'], 'scopes' => $scopes];
}

/** Revoke only a credential owned by this account. */
function mcp_pat_revoke(string $accountId, string $tokenId, ?PDO $pdo = null): bool
{
    if (!mcp_account_id_valid($accountId) || preg_match('/^[a-f0-9]{24}$/D', $tokenId) !== 1) return false;
    $statement = ($pdo ?? mcp_db())->prepare('UPDATE mcp_personal_access_tokens
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE token_id = :token_id AND account_id = :account_id AND revoked_at IS NULL');
    $statement->execute(['token_id' => $tokenId, 'account_id' => $accountId]);
    return $statement->rowCount() === 1;
}

/** @return list<array{id:string,label:string,scopes:string,expires_at:string,created_at:string}> */
function mcp_pat_list(string $accountId, ?PDO $pdo = null): array
{
    $statement = ($pdo ?? mcp_db())->prepare('SELECT token_id AS id, label, scopes, expires_at, created_at
        FROM mcp_personal_access_tokens
        WHERE account_id = :account_id AND revoked_at IS NULL AND expires_at > :now
        ORDER BY created_at DESC, id DESC LIMIT 30');
    $statement->execute(['account_id' => $accountId, 'now' => gmdate('Y-m-d H:i:s')]);
    return $statement->fetchAll(PDO::FETCH_ASSOC);
}
