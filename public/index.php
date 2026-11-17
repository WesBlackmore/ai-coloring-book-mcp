<?php

declare(strict_types=1);

/*
 * One front controller for the whole server. With PHP's built-in server:
 *
 *   php -S 127.0.0.1:8080 -t public public/index.php
 *
 * Routes: POST /mcp (the MCP endpoint), GET /download?artifact=art_... (bearer-token PDF download), and, when
 * MCP_OAUTH_ENABLED=1, the OAuth 2.1 discovery, authorize, token and JWKS paths.
 */

require_once __DIR__ . '/../src/autoload.php';

// Optional host wiring: a PHP file that calls mcp_register_hooks([...]) and may set
// $GLOBALS['mcp_oauth_account_resolver']. See the README.
$hooksFile = trim((string) getenv('MCP_HOOKS_FILE'));
if ($hooksFile !== '' && is_file($hooksFile)) require $hooksFile;

$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);

if ($path === '/mcp') {
    mcp_serve_http();
    return;
}

if ($path === '/download') {
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    $authorization = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    $principal = mcp_pat_authenticate($authorization);
    if ($principal === null && trim((string) getenv('MCP_OAUTH_ENABLED')) === '1'
        && preg_match('/^(?i:Bearer) ([A-Za-z0-9._~-]{1,8192})$/D', $authorization, $match)) {
        $principal = mcp_oauth_authenticate_access_token($match[1]);
    }
    if ($principal === null) {
        header('WWW-Authenticate: Bearer realm="AI Coloring Book MCP"');
        http_response_code(401);
        return;
    }
    if (array_diff([MCP_PAT_READ_SCOPE, MCP_PAT_EXPORT_SCOPE], $principal['scopes']) !== []) {
        http_response_code(403);
        return;
    }
    $artifact = (string) ($_GET['artifact'] ?? '');
    $download = mcp_coloring_export_download_file($principal['account_id'], $artifact);
    if ($download === null) {
        http_response_code(404);
        return;
    }
    header('Content-Type: application/pdf');
    header('Content-Length: ' . $download['size']);
    header('Content-Disposition: attachment; filename="' . $download['artifact_id'] . '.pdf"');
    readfile($download['file']);
    return;
}

if (trim((string) getenv('MCP_OAUTH_ENABLED')) === '1'
    && in_array($path, ['/.well-known/oauth-authorization-server', '/.well-known/oauth-protected-resource/mcp',
        '/oauth/jwks.json', '/oauth/authorize', '/oauth/token'], true)) {
    mcp_oauth_http_route($path);
}

http_response_code(404);
