<?php

declare(strict_types=1);

/*
 * Self-check suite: assert-based, no framework, no network, exits non-zero on failure.
 * All engine providers are fakes (the engine's coloring_worker_providers seam) and OpenAI moderation is stubbed.
 *
 *   php tools/selfcheck.php
 */

if (PHP_SAPI !== 'cli') exit(1);

$work = sys_get_temp_dir() . '/ai-coloring-book-mcp-selfcheck-' . bin2hex(random_bytes(4));
mkdir($work, 0775, true);
putenv('COLORING_DATA_DIR=' . $work);
putenv('COLORING_DATABASE_PATH=' . $work . '/selfcheck.db');
putenv('OPENAI_API_KEY');
putenv('COLORING_READY_WEBHOOK');
putenv('COLORING_WORKER_SPAWN=0');
putenv('MCP_OAUTH_ENABLED=0');
putenv('MCP_PAT_PEPPER');
ini_set('error_log', $work . '/php-error.log');
register_shutdown_function(static function () use ($work): void {
    exec('rm -rf ' . escapeshellarg($work));
});

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/fake-providers.php';

use Nyholm\Psr7\ServerRequest;
use Mcp\Server\Transport\StreamableHttpTransport;

$checks = 0;
$failures = [];
function check(string $label, bool $passed): void
{
    global $checks, $failures;
    $checks++;
    if (!$passed) $failures[] = $label;
}

/** The error code of a McpPlanError thrown by the callback, or null when nothing (or something else) was thrown. */
function error_code_of(callable $callback): ?string
{
    try {
        $callback();
    } catch (McpPlanError $error) {
        return $error->errorCode;
    } catch (Throwable) {
        return 'other';
    }
    return null;
}

function image_bytes(int $width, int $height): string
{
    $image = imagecreatetruecolor($width, $height);
    imagefill($image, 0, 0, imagecolorallocate($image, 200, 220, 255));
    ob_start();
    imagepng($image);
    return (string) ob_get_clean();
}

function moderation_result(array $flagged = []): array
{
    $categories = [];
    foreach (['sexual', 'sexual/minors', 'violence/graphic', 'self-harm/instructions', 'illicit', 'illicit/violent',
        'hate/threatening', 'harassment/threatening'] as $category) {
        $categories[$category] = in_array($category, $flagged, true);
    }
    return ['flagged' => $flagged !== [], 'categories' => $categories];
}

/** Build, queue and finish one book for an account through the MCP handlers. @return array{id:string,revision:int} */
function make_ready_book(string $account, string $commandId): array
{
    $book = mcp_coloring_create($account, $commandId, fake_create_request());
    $quote = mcp_coloring_quote($account, $book['book_id'], $book['plan_revision']);
    mcp_coloring_start($account, $book['book_id'], $quote['quote_id'], $book['plan_revision']);
    if (!fake_run_worker_until_ready()) throw new RuntimeException('book did not finish');
    return ['id' => $book['book_id'], 'revision' => $book['plan_revision']];
}

function rpc(array $message, ?string $session = null, string $account = 'acct-a'): array
{
    $headers = ['Content-Type' => 'application/json', 'Accept' => 'application/json, text/event-stream'];
    if ($session !== null) $headers['Mcp-Session-Id'] = $session;
    $request = new ServerRequest('POST', 'http://localhost/mcp', $headers, json_encode($message));
    $response = mcp_coloring_server($account, str_repeat('a', 24))->run(new StreamableHttpTransport($request));
    $body = (string) $response->getBody();
    return ['status' => $response->getStatusCode(), 'session' => $response->getHeaderLine('Mcp-Session-Id'),
        'json' => json_decode($body, true)];
}

fake_providers_install();
$calls = &$GLOBALS['fake_provider_calls'];

/* 1. Schema */
$pdo = mcp_db();
mcp_bootstrap_schema($pdo);
$tables = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table'")->fetchAll(PDO::FETCH_COLUMN);
foreach (['coloring_projects', 'mcp_personal_access_tokens', 'mcp_coloring_books', 'mcp_coloring_quotes', 'mcp_charge_ledger',
    'mcp_coloring_export_artifacts', 'mcp_oauth_grants', 'mcp_oauth_pending_authorizations'] as $table) {
    check("schema: $table exists", in_array($table, $tables, true));
}
check('schema: bootstrap is idempotent', $pdo->query('PRAGMA journal_mode')->fetchColumn() === 'wal');

/* 2. PATs */
$all = [MCP_PAT_READ_SCOPE, MCP_PAT_WRITE_SCOPE, MCP_PAT_EXPORT_SCOPE];
$pat = mcp_pat_issue('acct-a', 'full', 1, null, $all);
$principal = mcp_pat_authenticate('Bearer ' . $pat['token']);
check('pat: issued token authenticates', $principal !== null && $principal['account_id'] === 'acct-a' && $principal['scopes'] === $all);
$stored = $pdo->prepare('SELECT COUNT(*) FROM mcp_personal_access_tokens WHERE secret_hash = ?');
$stored->execute([$pat['token']]);
check('pat: the raw token is not stored', (int) $stored->fetchColumn() === 0);
check('pat: wrong secret is rejected', mcp_pat_authenticate('Bearer mcp_pat_' . $pat['id'] . '_' . str_repeat('0', 64)) === null);
check('pat: malformed header is rejected', mcp_pat_authenticate('Bearer nope') === null && mcp_pat_authenticate('') === null);
$revoked = mcp_pat_issue('acct-a', 'to revoke', 1);
check('pat: other account cannot revoke', mcp_pat_revoke('acct-b', $revoked['id']) === false
    && mcp_pat_authenticate('Bearer ' . $revoked['token']) !== null);
check('pat: owner revokes', mcp_pat_revoke('acct-a', $revoked['id']) === true);
check('pat: a revoked token is rejected', mcp_pat_authenticate('Bearer ' . $revoked['token']) === null);
$expired = mcp_pat_issue('acct-a', 'expiring', 1);
$pdo->prepare("UPDATE mcp_personal_access_tokens SET expires_at = '2000-01-01 00:00:00' WHERE token_id = ?")->execute([$expired['id']]);
check('pat: an expired token is rejected', mcp_pat_authenticate('Bearer ' . $expired['token']) === null);
check('pat: READ scope is mandatory', error_code_of(static fn() => mcp_pat_issue('acct-a', 'x', 1, null, [MCP_PAT_WRITE_SCOPE])) === 'other');
check('pat: bad account id refused', error_code_of(static fn() => mcp_pat_issue('has spaces', 'x')) === 'other');
putenv('MCP_PAT_PEPPER=selfcheck-pepper');
$peppered = mcp_pat_issue('acct-a', 'peppered', 1);
check('pat: pepper token authenticates', mcp_pat_authenticate('Bearer ' . $peppered['token']) !== null);
putenv('MCP_PAT_PEPPER');
check('pat: pepper change invalidates the token', mcp_pat_authenticate('Bearer ' . $peppered['token']) === null);
check('pat: list shows only live tokens', count(mcp_pat_list('acct-a')) >= 2 && count(mcp_pat_list('acct-b')) === 0);

/* 3. Scope enforcement and the exact tool surface */
$readWrite = mcp_pat_issue('acct-a', 'no export', 1, null, [MCP_PAT_READ_SCOPE, MCP_PAT_WRITE_SCOPE]);
$noExport = mcp_pat_authenticate('Bearer ' . $readWrite['token']);
check('scopes: an EXPORT-less token cannot call prepare_coloring_pdf',
    mcp_missing_scopes('prepare_coloring_pdf', $noExport['scopes']) === [MCP_PAT_EXPORT_SCOPE]);
foreach (['get_coloring_pdf', 'prepare_coloring_cover_wrap', 'get_coloring_cover_wrap'] as $tool) {
    check("scopes: $tool needs EXPORT", mcp_missing_scopes($tool, $noExport['scopes']) === [MCP_PAT_EXPORT_SCOPE]);
}
check('scopes: write tools are open to a READ+WRITE token', mcp_missing_scopes('create_coloring_book', $noExport['scopes']) === []
    && mcp_missing_scopes('start_coloring_book', $noExport['scopes']) === []);
$readOnly = mcp_pat_authenticate('Bearer ' . mcp_pat_issue('acct-a', 'ro', 1)['token']);
check('scopes: a READ-only token cannot create, quote, start or apply a cover',
    count(array_filter(['create_coloring_book', 'quote_coloring_book', 'start_coloring_book', 'apply_custom_coloring_cover'],
        static fn(string $tool): bool => mcp_missing_scopes($tool, $readOnly['scopes']) === [MCP_PAT_WRITE_SCOPE])) === 4);
check('scopes: reads need only READ', mcp_missing_scopes('get_coloring_book', $readOnly['scopes']) === []
    && mcp_missing_scopes('list_my_coloring_books', $readOnly['scopes']) === []);

$init = rpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => ['protocolVersion' => '2025-06-18',
    'capabilities' => new stdClass(), 'clientInfo' => ['name' => 'selfcheck', 'version' => '1']]]);
rpc(['jsonrpc' => '2.0', 'method' => 'notifications/initialized'], $init['session']);
$list = rpc(['jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/list'], $init['session']);
$names = array_column($list['json']['result']['tools'] ?? [], 'name');
$expectedTools = ['list_my_coloring_books', 'get_coloring_book', 'create_coloring_book', 'quote_coloring_book',
    'start_coloring_book', 'apply_custom_coloring_cover', 'prepare_coloring_pdf', 'get_coloring_pdf',
    'prepare_coloring_cover_wrap', 'get_coloring_cover_wrap'];
check('server: tools/list is exactly the ten coloring tools', $names !== [] && array_diff($names, $expectedTools) === []
    && array_diff($expectedTools, $names) === [] && count($names) === 10);
check('server: no ebook tool is exposed', count(array_filter($names, static fn(string $name): bool => str_contains($name, 'ebook'))) === 0);
check('server: scope map covers every tool', array_keys(mcp_tool_scope_map()) === $expectedTools);
check('server: KDP 300 PPI rule is in the guidance text', str_contains(MCP_INSTRUCTIONS, 'Never call a below-300-PPI wrap KDP-ready'));
$resources = rpc(['jsonrpc' => '2.0', 'id' => 3, 'method' => 'resources/list'], $init['session']);
check('server: the coloring viewer resource is listed', in_array(MCP_COLORING_VIEWER_RESOURCE_URI,
    array_column($resources['json']['result']['resources'] ?? [], 'uri'), true));
$viaRpc = rpc(['jsonrpc' => '2.0', 'id' => 4, 'method' => 'tools/call', 'params' => ['name' => 'list_my_coloring_books', 'arguments' => new stdClass()]], $init['session']);
check('server: a tool call round-trips through the SDK', ($viaRpc['json']['result']['structuredContent']['books'] ?? null) === []);

/* 4. create -> quote -> start -> worker -> pdf, default free, no billing wired */
$book = mcp_coloring_create('acct-a', '3f2b1c0e-9d8a-4b7c-a6e5-4d3c2b1a0f9e', fake_create_request());
check('flow: create saves a planned book', $book['state'] === 'planned' && $book['drawings_total'] === 16 && str_starts_with($book['book_id'], 'cb_'));
$replay = mcp_coloring_create('acct-a', '3f2b1c0e-9d8a-4b7c-a6e5-4d3c2b1a0f9e', fake_create_request());
check('flow: a retried create command returns the same book', $replay['book_id'] === $book['book_id']);
$changed = fake_create_request();
$changed['plan']['title'] = 'A Different Title';
check('flow: a reused command id with new content conflicts', error_code_of(static fn() => mcp_coloring_create('acct-a', '3f2b1c0e-9d8a-4b7c-a6e5-4d3c2b1a0f9e', $changed)) === 'COMMAND_CONFLICT');
check('flow: nothing was drawn at create', $calls['page'] === 0 && $calls['plan'] === 0);
$quote = mcp_coloring_quote('acct-a', $book['book_id'], $book['plan_revision']);
check('flow: the default quote is free and startable', $quote['cost'] === 0 && $quote['can_start'] === true);
check('flow: start with a stale revision conflicts', error_code_of(static fn() => mcp_coloring_start('acct-a', $book['book_id'], $quote['quote_id'], 9)) === 'REVISION_CONFLICT');
$started = mcp_coloring_start('acct-a', $book['book_id'], $quote['quote_id'], $book['plan_revision']);
check('flow: start queues the book and charges nothing', $started['state'] === 'queued' && $started['charged'] === 0);
$startedAgain = mcp_coloring_start('acct-a', $book['book_id'], $quote['quote_id'], $book['plan_revision']);
check('flow: a retried start is harmless', $startedAgain['book_id'] === $book['book_id']
    && (int) $pdo->query("SELECT COUNT(*) FROM mcp_charge_ledger WHERE quote_id = '" . $quote['quote_id'] . "'")->fetchColumn() === 1);
check('flow: the worker finishes through the fake provider', fake_run_worker_until_ready());
check('flow: sixteen drawings were drawn by the engine, the plan provider never ran', $calls['page'] === 16 && $calls['plan'] === 0 && $calls['cover'] === 1);
$status = mcp_coloring_status('acct-a', $book['book_id']);
check('flow: status reports a ready book with a cover', $status['payload']['state'] === 'ready' && $status['payload']['cover_ready'] === true
    && $status['payload']['drawings_done'] === 16 && count($status['images']) >= 4);
$export = mcp_prepare_coloring_pdf('acct-a', $book['book_id']);
check('flow: prepare queues a PDF', $export['state'] === 'queued' && str_starts_with($export['artifact_id'], 'art_'));
check('flow: preparing again reuses the artifact', mcp_prepare_coloring_pdf('acct-a', $book['book_id'])['artifact_id'] === $export['artifact_id']);
$worker = mcp_coloring_export_worker_run();
$ready = mcp_get_coloring_pdf('acct-a', $book['book_id'], $export['artifact_id']);
check('flow: the export worker renders the PDF', $worker['ready'] === 1 && $ready['state'] === 'ready' && $ready['is_current'] === true
    && $ready['download_url'] !== null && str_contains($ready['download_url'], $export['artifact_id']));
$download = mcp_coloring_export_download_file('acct-a', $export['artifact_id']);
check('flow: the artifact is a real PDF', $download !== null && str_starts_with((string) file_get_contents($download['file'], false, null, 0, 5), '%PDF-')
    && filesize($download['file']) === $ready['file_size']);
$wrap = mcp_prepare_coloring_cover_wrap('acct-a', $book['book_id']);
mcp_coloring_export_worker_run();
$wrapReady = mcp_get_coloring_cover_wrap('acct-a', $book['book_id'], $wrap['artifact_id']);
check('flow: the KDP cover wrap renders', $wrapReady['state'] === 'ready' && $wrapReady['export_type'] === MCP_COLORING_EXPORT_KDP_WRAP);
check('flow: the wrong export type cannot read an artifact', error_code_of(static fn() => mcp_get_coloring_pdf('acct-a', $book['book_id'], $wrap['artifact_id'])) === 'NOT_AVAILABLE');

/* 5. The charge hook */
$before = $calls['page'];
$deniedBook = mcp_coloring_create('acct-a', '11111111-1111-4111-8111-111111111111', fake_create_request());
$seen = [];
mcp_register_hooks([
    'quote_cost' => static function (array $context) use (&$seen): array {
        $seen['quote'] = $context;
        return ['cost' => 7, 'unit' => 'credits', 'message' => '7 credits'];
    },
    'charge' => static function (array $context) use (&$seen): array {
        $seen['charge'] = $context;
        return ['approved' => false, 'reason' => 'Insufficient balance'];
    },
]);
$quote = mcp_coloring_quote('acct-a', $deniedBook['book_id'], $deniedBook['plan_revision']);
check('hook: quote_cost sets the quoted cost', $quote['cost'] === 7 && $quote['unit'] === 'credits'
    && $seen['quote']['account_id'] === 'acct-a' && $seen['quote']['book_token'] === $deniedBook['book_id']
    && $seen['quote']['drawings_total'] === 16);
check('hook: a denied charge stops the start', error_code_of(static fn() => mcp_coloring_start('acct-a', $deniedBook['book_id'], $quote['quote_id'], 1)) === 'CHARGE_DENIED');
check('hook: the charge hook got the idempotency key and amount', $seen['charge']['idempotency_key'] === $quote['quote_id'] && $seen['charge']['cost'] === 7);
fake_run_worker_until_ready(3);
$deniedRow = mcp_coloring_owned('acct-a', $deniedBook['book_id']);
check('hook: a denied start runs no generation', $calls['page'] === $before && $deniedRow['status'] === 'planned');
$ledger = $pdo->query("SELECT decision, amount, reason FROM mcp_charge_ledger WHERE quote_id = '" . $quote['quote_id'] . "'")->fetchAll(PDO::FETCH_ASSOC);
check('hook: the denial is in the ledger', count($ledger) === 1 && $ledger[0]['decision'] === 'denied' && (int) $ledger[0]['amount'] === 7
    && $ledger[0]['reason'] === 'Insufficient balance');
check('hook: a denied quote stays unused', $pdo->query("SELECT consumed_at FROM mcp_coloring_quotes WHERE quote_id = '" . $quote['quote_id'] . "'")->fetchColumn() === null);
// A price that moves between quote and start is refused.
mcp_register_hooks(['quote_cost' => static fn(array $context): int => 9, 'charge' => static fn(array $context): bool => true]);
check('hook: a price change since the quote conflicts', error_code_of(static fn() => mcp_coloring_start('acct-a', $deniedBook['book_id'], $quote['quote_id'], 1)) === 'REVISION_CONFLICT');
// Approve: the charge runs, the engine runs.
mcp_register_hooks(['quote_cost' => static fn(array $context): int => 7, 'charge' => static function (array $context) use (&$seen): array {
    $seen['approved'] = $context;
    return ['approved' => true, 'reference' => 'txn-1'];
}]);
$approvedStart = mcp_coloring_start('acct-a', $deniedBook['book_id'], $quote['quote_id'], 1);
check('hook: an approved charge starts generation', $approvedStart['state'] === 'queued' && $approvedStart['charged'] === 7);
fake_run_worker_until_ready();
check('hook: the engine ran after approval', $calls['page'] === $before + 16);
$ledger = $pdo->query("SELECT decision, reference FROM mcp_charge_ledger WHERE quote_id = '" . $quote['quote_id'] . "' ORDER BY id")->fetchAll(PDO::FETCH_ASSOC);
check('hook: both decisions are in the ledger', count($ledger) === 2 && $ledger[0]['decision'] === 'denied' && $ledger[1]['decision'] === 'approved' && $ledger[1]['reference'] === 'txn-1');
mcp_register_hooks(['quote_cost' => static fn(array $context): array => ['cost' => 1, 'can_start' => false, 'message' => 'Out of allowance'], 'charge' => null]);
$blockedBook = mcp_coloring_create('acct-a', '22222222-2222-4222-8222-222222222222', fake_create_request());
$blockedQuote = mcp_coloring_quote('acct-a', $blockedBook['book_id'], 1);
check('hook: can_start=false is reported in the quote and blocks the start', $blockedQuote['can_start'] === false
    && error_code_of(static fn() => mcp_coloring_start('acct-a', $blockedBook['book_id'], $blockedQuote['quote_id'], 1)) === 'CHARGE_DENIED');
mcp_register_hooks(['quote_cost' => null, 'charge' => null]);
check('hook: with no hooks everything is free again', mcp_coloring_quote('acct-a', $blockedBook['book_id'], 1)['cost'] === 0);
check('hook: a non-callable hook is refused', error_code_of(static fn() => mcp_register_hooks(['charge' => 'no_such_function'])) === 'other');

/* 6. Content safety */
$textCalls = 0;
$GLOBALS['mcp_content_safety_provider'] = static function (string $text) use (&$textCalls): array {
    $textCalls++;
    return moderation_result(str_contains($text, 'FORBIDDEN') ? ['sexual'] : []);
};
$before = (int) $pdo->query('SELECT COUNT(*) FROM mcp_coloring_books')->fetchColumn();
mcp_coloring_create('acct-a', '33333333-3333-4333-8333-333333333333', fake_create_request());
check('safety: the text gate is invoked on create', $textCalls >= 1);
$unsafe = fake_create_request();
$unsafe['plan']['scenes'][2]['description'] = 'FORBIDDEN content';
$unsafeCode = error_code_of(static fn() => mcp_coloring_create('acct-a', '44444444-4444-4444-8444-444444444444', $unsafe));
check('safety: a blocked plan is refused and nothing is saved', $unsafeCode === 'CONTENT_NOT_ALLOWED'
    && (int) $pdo->query('SELECT COUNT(*) FROM mcp_coloring_books')->fetchColumn() === $before + 1);
$GLOBALS['mcp_content_safety_provider'] = static function (string $text): array {
    throw new RuntimeException('moderation outage');
};
check('safety: with moderation configured an outage fails closed', error_code_of(static fn() => mcp_coloring_create('acct-a', '55555555-5555-4555-8555-555555555555', fake_create_request())) === 'SAFETY_CHECK_UNAVAILABLE');
unset($GLOBALS['mcp_content_safety_provider']);

$imageCalls = 0;
$blockImages = false;
$GLOBALS['mcp_content_safety_image_provider'] = static function (array $images) use (&$imageCalls, &$blockImages): array {
    $imageCalls++;
    return moderation_result($blockImages ? ['sexual'] : []);
};
$GLOBALS['mcp_content_safety_image_passes'] = [];
$seenImages = mcp_coloring_status('acct-a', $book['book_id']);
check('safety: the image gate screens returned artwork', $imageCalls >= 1 && count($seenImages['images']) >= 4);
$blockImages = true;
$GLOBALS['mcp_content_safety_image_passes'] = [];
check('safety: a blocked image aborts the status read', error_code_of(static fn() => mcp_coloring_status('acct-a', $book['book_id'])) === 'CONTENT_NOT_ALLOWED');
check('safety: a blocked image aborts a direct image check', error_code_of(static fn() => mcp_content_safety_assert_image(image_bytes(40, 40))) === 'CONTENT_NOT_ALLOWED');
unset($GLOBALS['mcp_content_safety_image_provider']);
$GLOBALS['mcp_content_safety_image_passes'] = [];
check('safety: the skip is logged as a warning', str_contains((string) file_get_contents($work . '/php-error.log'), 'moderation is SKIPPED'));
check('safety: with no key the gate is skipped, not a hard failure', mcp_content_safety_active() === false
    && error_code_of(static fn() => mcp_content_safety_assert_image(image_bytes(41, 41))) === null);
putenv('MCP_CONTENT_SAFETY=0');
putenv('OPENAI_API_KEY=sk-dummy-selfcheck-value');
check('safety: MCP_CONTENT_SAFETY=0 switches it off even with a key', mcp_content_safety_active() === false);
putenv('MCP_CONTENT_SAFETY');
check('safety: a key turns it on by default', mcp_content_safety_active() === true);
putenv('OPENAI_API_KEY');

/* 7. Ownership isolation */
check('owner: account B cannot read account A\'s book', error_code_of(static fn() => mcp_coloring_status('acct-b', $book['book_id'])) === 'NOT_AVAILABLE');
check('owner: account B\'s library is empty and A\'s is not', mcp_coloring_list('acct-b')['books'] === [] && count(mcp_coloring_list('acct-a')['books']) >= 3);
check('owner: account B cannot quote or start it', error_code_of(static fn() => mcp_coloring_quote('acct-b', $book['book_id'], 1)) === 'NOT_AVAILABLE'
    && error_code_of(static fn() => mcp_coloring_start('acct-b', $book['book_id'], $quote['quote_id'], 1)) === 'NOT_AVAILABLE');
check('owner: account B cannot prepare or read exports', error_code_of(static fn() => mcp_prepare_coloring_pdf('acct-b', $book['book_id'])) === 'NOT_AVAILABLE'
    && error_code_of(static fn() => mcp_get_coloring_pdf('acct-b', $book['book_id'], $export['artifact_id'])) === 'NOT_AVAILABLE'
    && error_code_of(static fn() => mcp_prepare_coloring_cover_wrap('acct-b', $book['book_id'])) === 'NOT_AVAILABLE');
check('owner: account B cannot download A\'s artifact', mcp_coloring_export_download_file('acct-b', $export['artifact_id']) === null);
check('owner: account B cannot replace A\'s cover', error_code_of(static fn() => mcp_apply_custom_coloring_cover('acct-b', $book['book_id'],
    ['file_id' => 'f', 'download_url' => 'https://x.invalid/a.png'], mcp_coloring_cover_revision(mcp_coloring_owned('acct-a', $book['book_id'])))) === 'NOT_AVAILABLE');
$sameCommand = mcp_coloring_create('acct-b', '3f2b1c0e-9d8a-4b7c-a6e5-4d3c2b1a0f9e', fake_create_request());
check('owner: a command id is scoped to its account', $sameCommand['book_id'] !== $book['book_id']);
check('owner: the engine row carries the account as owner_ref', mcp_coloring_owned('acct-b', $sameCommand['book_id'])['owner_ref'] === 'acct-b');
check('owner: an unknown or malformed id is simply unavailable', mcp_coloring_owned('acct-a', 'cb_' . str_repeat('0', 24)) === null
    && mcp_coloring_owned('acct-a', "cb_' OR 1=1 --") === null && mcp_coloring_owned('', $book['book_id']) === null);

/* 8. The 300 PPI cover check */
$low = mcp_coloring_cover_source_quality(image_bytes(1200, 1565));
check('ppi: a low-resolution cover is flagged', $low['cover_source_meets_300ppi'] === false && $low['cover_source_ppi_x'] < 300
    && str_contains($low['cover_source_resolution_note'], 'do not submit it as KDP-ready'));
$high = mcp_coloring_cover_source_quality(image_bytes(2600, 3400));
check('ppi: a 300 PPI cover passes', $high['cover_source_meets_300ppi'] === true && $high['cover_source_ppi_x'] >= 300
    && !str_contains($high['cover_source_resolution_note'], 'do not submit'));
$unknown = mcp_coloring_cover_source_quality('not an image');
check('ppi: an unreadable cover is never called KDP-ready', $unknown['cover_source_meets_300ppi'] === null
    && str_contains($unknown['cover_source_resolution_note'], 'Do not treat the wrap as KDP-ready'));

$GLOBALS['coloring_cover_providers'] = ['outline' => static fn(string $jpeg, array $project, array $meta): string => image_bytes(300, 400)];
$fetched = 0;
$GLOBALS['mcp_image_fetcher'] = static function (string $url) use (&$fetched): string {
    $fetched++;
    return image_bytes(1000, 1300);
};
$revision = mcp_coloring_cover_revision(mcp_coloring_owned('acct-a', $book['book_id']));
$applied = mcp_apply_custom_coloring_cover('acct-a', $book['book_id'], ['file_id' => 'file-1', 'download_url' => 'https://example.invalid/cover.png'], $revision);
check('ppi: a low-res custom cover is applied but flagged below 300 PPI', $applied['cover_source_meets_300ppi'] === false
    && $applied['cover_source_width_px'] === 1000 && str_contains($applied['message'], 'do not submit it as KDP-ready'));
check('ppi: the cover revision moved', $applied['cover_revision'] !== $revision);
check('ppi: a stale cover revision is refused', error_code_of(static fn() => mcp_apply_custom_coloring_cover('acct-a', $book['book_id'],
    ['file_id' => 'file-1', 'download_url' => 'https://example.invalid/cover.png'], $revision)) === 'REVISION_CONFLICT');
$oldPdf = mcp_get_coloring_pdf('acct-a', $book['book_id'], $export['artifact_id']);
check('stale: the PDF made before the cover change is stale and has no link', $oldPdf['state'] === 'stale' && $oldPdf['is_current'] === false && $oldPdf['download_url'] === null);
$newWrap = mcp_prepare_coloring_cover_wrap('acct-a', $book['book_id']);
check('ppi: the cover wrap export reports the low-res source', $newWrap['artifact_id'] !== $wrap['artifact_id']
    && $newWrap['cover_source_meets_300ppi'] === false && str_contains((string) $newWrap['cover_source_resolution_note'], 'KDP'));
mcp_coloring_export_worker_run();
$newWrap = mcp_get_coloring_cover_wrap('acct-a', $book['book_id'], $newWrap['artifact_id']);
check('ppi: the wrap still renders for personal printing', $newWrap['state'] === 'ready' && $newWrap['cover_source_meets_300ppi'] === false);
check('ppi: a non-image cover is refused', error_code_of(static function () use ($book): void {
    $GLOBALS['mcp_image_fetcher'] = static fn(string $url): string => 'not an image';
    mcp_apply_custom_coloring_cover('acct-a', $book['book_id'], ['file_id' => 'f', 'download_url' => 'https://example.invalid/x.png'],
        mcp_coloring_cover_revision(mcp_coloring_owned('acct-a', $book['book_id'])));
}) === 'INVALID_IMAGE');
check('ppi: only ChatGPT file hosts are fetched', error_code_of(static function (): void {
    unset($GLOBALS['mcp_image_fetcher']);
    mcp_chatgpt_image_bytes('https://evil.example.com/a.png');
}) === 'INVALID_IMAGE');

/* 9. The optional OAuth module: a full authorization-code and refresh flow against league/oauth2-server, in process */
if (class_exists(\League\OAuth2\Server\AuthorizationServer::class) && function_exists('openssl_pkey_new')) {
    $keyFile = $work . '/oauth-key.pem';
    openssl_pkey_export(openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]), $pem);
    file_put_contents($keyFile, $pem);
    chmod($keyFile, 0600);
    putenv('MCP_OAUTH_ENABLED=1');
    putenv('MCP_PUBLIC_BASE_URL=https://mcp.example.test');
    putenv('MCP_OAUTH_PRIVATE_KEY_PATH=' . $keyFile);
    putenv('MCP_OAUTH_KEY_ID=selfcheck-key');
    putenv('MCP_OAUTH_ENCRYPTION_KEY=' . \Defuse\Crypto\Key::createNewRandomKey()->saveToAsciiSafeString());
    require_once __DIR__ . '/../src/oauth/http.php';
    $config = mcp_oauth_http_config();
    check('oauth: config derives the endpoints from MCP_PUBLIC_BASE_URL', $config['resource'] === 'https://mcp.example.test/mcp'
        && $config['token_endpoint'] === 'https://mcp.example.test/oauth/token');
    $client = new \AiColoringBookMcp\OAuth\McpOAuthClientEntity(MCP_OAUTH_CHATGPT_CLIENT_ID, 'ChatGPT', ['https://chatgpt.com/connector/oauth/abc']);
    [$server, $repositories] = mcp_oauth_http_server($client);
    $verifier = bin2hex(random_bytes(32));
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    $params = ['client_id' => $client->getIdentifier(), 'redirect_uri' => 'https://chatgpt.com/connector/oauth/abc', 'response_type' => 'code',
        'scope' => 'books:read books:write', 'state' => str_repeat('s', 20), 'code_challenge' => $challenge,
        'code_challenge_method' => 'S256', 'resource' => $config['resource']];
    $authRequest = (new ServerRequest('GET', $config['authorization_endpoint']))->withQueryParams($params);
    $repositories->assertAuthorizationResource($authRequest);
    $authorization = $server->validateAuthorizationRequest($authRequest);
    $grantId = bin2hex(random_bytes(24));
    $pdo->prepare('INSERT INTO mcp_oauth_grants (grant_id, account_id, client_id, resource, scopes) VALUES (?, ?, ?, ?, ?)')
        ->execute([$grantId, 'acct-a', $client->getIdentifier(), $config['resource'], 'books:read books:write']);
    $repositories->setAuthorizationContext('acct-a', $grantId, $challenge, 'S256');
    $authorization->setUser(new \AiColoringBookMcp\OAuth\McpOAuthUserEntity('acct-a'));
    $authorization->setAuthorizationApproved(true);
    $redirect = $server->completeAuthorizationRequest($authorization, new \Nyholm\Psr7\Response())->getHeaderLine('Location');
    parse_str((string) parse_url($redirect, PHP_URL_QUERY), $callback);
    check('oauth: consent issues an authorization code to the allowlisted redirect', str_starts_with($redirect, 'https://chatgpt.com/connector/oauth/abc?')
        && isset($callback['code']) && mcp_oauth_http_issuer_callback_location($redirect, $config) !== null
        && mcp_oauth_http_issuer_callback_location('https://evil.example.com/cb?code=x', $config) === null);
    $tokenRequest = static fn(array $body): ServerRequest => (new ServerRequest('POST', $config['token_endpoint'],
        ['Content-Type' => 'application/x-www-form-urlencoded']))->withParsedBody($body + ['client_id' => $client->getIdentifier(), 'resource' => $config['resource']]);
    [$server, $repositories] = mcp_oauth_http_server($client);
    $response = $repositories->respondToTokenRequest($server, $tokenRequest(['grant_type' => 'authorization_code', 'code' => $callback['code'],
        'redirect_uri' => $params['redirect_uri'], 'code_verifier' => $verifier]), new \Nyholm\Psr7\Response());
    $tokens = json_decode((string) $response->getBody(), true);
    check('oauth: the code exchanges for an access and a refresh token', $response->getStatusCode() === 200 && isset($tokens['access_token'], $tokens['refresh_token']));
    $oauthPrincipal = mcp_oauth_authenticate_access_token($tokens['access_token']);
    check('oauth: the access token authenticates as the grant\'s account and scopes', $oauthPrincipal !== null
        && $oauthPrincipal['account_id'] === 'acct-a' && $oauthPrincipal['scopes'] === ['books:read', 'books:write']);
    check('oauth: a garbage bearer is rejected', mcp_oauth_authenticate_access_token('not.a.jwt') === null);
    $refreshBody = ['grant_type' => 'refresh_token', 'refresh_token' => $tokens['refresh_token']];
    [$server, $repositories] = mcp_oauth_http_server($client);
    $rotated = json_decode((string) $repositories->respondToTokenRequest($server, $tokenRequest($refreshBody), new \Nyholm\Psr7\Response())->getBody(), true);
    check('oauth: refresh rotates to a new working access token', isset($rotated['access_token'])
        && (mcp_oauth_authenticate_access_token($rotated['access_token'])['account_id'] ?? null) === 'acct-a');
    [$server, $repositories] = mcp_oauth_http_server($client);
    check('oauth: replaying the old refresh token is rejected', error_code_of(static fn() => $repositories->respondToTokenRequest($server,
        $tokenRequest($refreshBody), new \Nyholm\Psr7\Response())) === 'other');
    check('oauth: replay revoked the whole family', mcp_oauth_authenticate_access_token($rotated['access_token']) === null);
    $anotherGrant = mcp_oauth_store_validate_access_token('x' . str_repeat('y', 20), 'acct-b', $config['resource'], ['books:read']);
    check('oauth: an unknown token id never validates', $anotherGrant === null);
    putenv('MCP_OAUTH_ENABLED=0');
} else {
    echo "oauth: league/oauth2-server or ext-openssl not available, OAuth checks skipped (PAT-only install)\n";
}

echo $checks, ' checks, ', count($failures), " failures\n";
foreach ($failures as $failure) echo '  FAIL: ', $failure, "\n";
exit($failures === [] ? 0 : 1);
