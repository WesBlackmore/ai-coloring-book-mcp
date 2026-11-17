<?php

declare(strict_types=1);

/*
 * The package shares the engine's SQLite database (the engine owns coloring_projects, this package owns the
 * mcp_* tables). The connection, WAL pragmas and data directory come from the engine's db(); this file adds the
 * package schema on top. Every owner column is account_id TEXT, an opaque string the host chooses.
 */

/** The shared connection with the package schema applied once per connection. */
function mcp_db(): PDO
{
    static $prepared = null;
    $pdo = db();
    if ($prepared !== $pdo) {
        mcp_bootstrap_schema($pdo);
        $prepared = $pdo;
    }
    return $pdo;
}

/** Idempotent. Safe to call on every request. */
function mcp_bootstrap_schema(PDO $pdo): void
{
    $statements = [
        "CREATE TABLE IF NOT EXISTS mcp_personal_access_tokens (
            id INTEGER PRIMARY KEY,
            token_id TEXT NOT NULL UNIQUE,
            secret_hash TEXT NOT NULL,
            account_id TEXT NOT NULL,
            label TEXT NOT NULL,
            scopes TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        'CREATE INDEX IF NOT EXISTS mcp_pat_account ON mcp_personal_access_tokens (account_id, revoked_at)',
        "CREATE TABLE IF NOT EXISTS mcp_coloring_books (
            id INTEGER PRIMARY KEY,
            book_token TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            project_id INTEGER NOT NULL REFERENCES coloring_projects (id) ON DELETE CASCADE,
            create_command_id TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            current_revision INTEGER NOT NULL DEFAULT 1,
            current_plan_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (account_id, create_command_id)
        )",
        'CREATE INDEX IF NOT EXISTS mcp_coloring_books_account ON mcp_coloring_books (account_id, id)',
        "CREATE TABLE IF NOT EXISTS mcp_coloring_quotes (
            id INTEGER PRIMARY KEY,
            quote_id TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            book_token TEXT NOT NULL,
            plan_revision INTEGER NOT NULL,
            plan_hash TEXT NOT NULL,
            cost INTEGER NOT NULL DEFAULT 0,
            unit TEXT NOT NULL DEFAULT '',
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        // The admission ledger: one row per charge decision the host's hook made, approved or denied.
        "CREATE TABLE IF NOT EXISTS mcp_charge_ledger (
            id INTEGER PRIMARY KEY,
            account_id TEXT NOT NULL,
            book_token TEXT NOT NULL,
            quote_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            decision TEXT NOT NULL CHECK (decision IN ('approved', 'denied')),
            reason TEXT,
            reference TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        'CREATE INDEX IF NOT EXISTS mcp_charge_ledger_quote ON mcp_charge_ledger (quote_id)',
        "CREATE TABLE IF NOT EXISTS mcp_coloring_export_artifacts (
            id INTEGER PRIMARY KEY,
            artifact_id TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            project_id INTEGER NOT NULL REFERENCES coloring_projects (id) ON DELETE CASCADE,
            book_token TEXT NOT NULL,
            export_type TEXT NOT NULL DEFAULT 'coloring_book_pdf',
            render_key TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            cover_hash TEXT NOT NULL,
            renderer_version TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('queued', 'rendering', 'retry_wait', 'ready', 'expired', 'failed')),
            attempts INTEGER NOT NULL DEFAULT 0,
            retry_at TEXT,
            lease_token TEXT,
            lease_until TEXT,
            private_name TEXT,
            file_sha256 TEXT,
            file_size INTEGER,
            expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (project_id, render_key)
        )",
        'CREATE INDEX IF NOT EXISTS mcp_coloring_export_queue ON mcp_coloring_export_artifacts (state, retry_at, id)',
        'CREATE INDEX IF NOT EXISTS mcp_coloring_export_owner ON mcp_coloring_export_artifacts (account_id, book_token, id)',
        // OAuth 2.1 tables. Inert unless MCP_OAUTH_ENABLED=1 loads src/oauth/.
        "CREATE TABLE IF NOT EXISTS mcp_oauth_grants (
            id INTEGER PRIMARY KEY,
            grant_id TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            scopes TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        'CREATE INDEX IF NOT EXISTS mcp_oauth_grants_live ON mcp_oauth_grants (account_id, client_id, revoked_at)',
        "CREATE TABLE IF NOT EXISTS mcp_oauth_authorization_codes (
            id INTEGER PRIMARY KEY,
            code_id TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            grant_id TEXT NOT NULL REFERENCES mcp_oauth_grants (grant_id) ON DELETE CASCADE,
            client_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scopes TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            code_challenge_method TEXT NOT NULL CHECK (code_challenge_method IN ('s256')),
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        "CREATE TABLE IF NOT EXISTS mcp_oauth_access_tokens (
            id INTEGER PRIMARY KEY,
            token_id TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            grant_id TEXT NOT NULL REFERENCES mcp_oauth_grants (grant_id) ON DELETE CASCADE,
            client_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            scopes TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        "CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_tokens (
            id INTEGER PRIMARY KEY,
            token_id TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            grant_id TEXT NOT NULL REFERENCES mcp_oauth_grants (grant_id) ON DELETE CASCADE,
            client_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            family_id TEXT NOT NULL,
            access_token_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            replaced_by TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        'CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_family ON mcp_oauth_refresh_tokens (family_id, revoked_at)',
        "CREATE TABLE IF NOT EXISTS mcp_oauth_cimd_cache (
            id INTEGER PRIMARY KEY,
            client_id TEXT NOT NULL UNIQUE,
            metadata_json TEXT NOT NULL,
            metadata_sha256 TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        "CREATE TABLE IF NOT EXISTS mcp_oauth_pending_authorizations (
            id INTEGER PRIMARY KEY,
            request_hash TEXT NOT NULL UNIQUE,
            session_binding TEXT NOT NULL,
            account_id TEXT NOT NULL,
            params_json TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    ];
    foreach ($statements as $sql) $pdo->exec($sql);
}
