<?php

declare(strict_types=1);

/*
 * Single entry point for the package. Loads Composer's autoloader, the AI Coloring Book Engine
 * (cloned into ./engine, or wherever COLORING_ENGINE_PATH points) and the MCP source files.
 * The OAuth module under src/oauth/ is loaded only when MCP_OAUTH_ENABLED=1.
 */

const MCP_PACKAGE_ROOT = __DIR__ . '/..';

require_once MCP_PACKAGE_ROOT . '/vendor/autoload.php';

/** Absolute path of the engine checkout. The engine is required, never vendored into this repo. */
function mcp_engine_path(): string
{
    $configured = trim((string) getenv('COLORING_ENGINE_PATH'));
    $path = realpath($configured !== '' ? $configured : MCP_PACKAGE_ROOT . '/engine');
    if ($path === false || !is_file($path . '/src/coloring_worker.php')) {
        throw new RuntimeException('AI Coloring Book Engine not found. Run "composer install-engine" '
            . '(git clone https://github.com/WesBlackmore/ai-coloring-book-engine engine) or set COLORING_ENGINE_PATH.');
    }
    if (!is_file($path . '/vendor/autoload.php')) {
        throw new RuntimeException('The engine has no vendor directory. Run "composer install" inside ' . $path . '.');
    }
    return $path;
}

$mcpEngine = mcp_engine_path();
require_once $mcpEngine . '/src/db.php';
require_once $mcpEngine . '/src/coloring_worker.php';
require_once $mcpEngine . '/src/coloring_pdf_cache.php';
unset($mcpEngine);

foreach (['db', 'mcp_common', 'mcp_db_transactions', 'mcp_auth', 'mcp_content_safety', 'mcp_tool_schemas',
    'mcp_custom_covers', 'mcp_quotes', 'mcp_admission', 'mcp_coloring', 'mcp_coloring_exports', 'mcp_server'] as $file) {
    require_once __DIR__ . '/' . $file . '.php';
}

if (trim((string) getenv('MCP_OAUTH_ENABLED')) === '1') {
    require_once __DIR__ . '/oauth/http.php';
}
