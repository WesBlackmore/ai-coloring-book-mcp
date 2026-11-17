<?php

declare(strict_types=1);

/** End SQLite transactions opened with BEGIN IMMEDIATE via SQL, not PDO::commit(). */
function mcp_db_immediate_commit(PDO $pdo): void
{
    $pdo->exec('COMMIT');
}

function mcp_db_immediate_rollback(PDO $pdo): void
{
    try {
        $pdo->exec('ROLLBACK');
    } catch (Throwable) {
        // SQLite may already have rolled the transaction back.
    }
}
