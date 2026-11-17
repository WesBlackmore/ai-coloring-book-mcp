<?php

declare(strict_types=1);

/*
 * Offline end-to-end example: MCP handlers -> engine -> interior PDF, with NO network and NO OpenAI key.
 *
 * The engine's AI providers are replaced by fakes through its seam ($GLOBALS['coloring_worker_providers']), so
 * the "art" is placeholder rings. The path under test is real: PAT issue and auth, the MCP create/quote/start
 * handlers, the engine worker, and the MCP PDF export queue and worker.
 *
 *   php examples/offline-example.php
 *
 * Needs the engine installed (see the README). Prints the absolute path of the finished interior PDF.
 */

if (PHP_SAPI !== 'cli') exit(1);

$work = sys_get_temp_dir() . '/ai-coloring-book-mcp-example-' . bin2hex(random_bytes(4));
mkdir($work, 0775, true);
putenv('COLORING_DATA_DIR=' . $work);
putenv('COLORING_DATABASE_PATH=' . $work . '/example.db');
putenv('OPENAI_API_KEY');
putenv('COLORING_READY_WEBHOOK');
putenv('COLORING_WORKER_SPAWN=0');
putenv('MCP_OAUTH_ENABLED=0');
register_shutdown_function(static function () use ($work): void {
    exec('rm -rf ' . escapeshellarg($work));
});

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/../tools/fake-providers.php';

function step(string $message): void
{
    echo $message, "\n";
}

fake_providers_install();

mcp_bootstrap_schema(mcp_db());
step('1. schema bootstrapped');

$pat = mcp_pat_issue('demo-account', 'offline example', 1, null,
    [MCP_PAT_READ_SCOPE, MCP_PAT_WRITE_SCOPE, MCP_PAT_EXPORT_SCOPE]);
$principal = mcp_pat_authenticate('Bearer ' . $pat['token']);
if ($principal === null || $principal['account_id'] !== 'demo-account') {
    fwrite(STDERR, "PAT did not authenticate\n");
    exit(1);
}
step('2. PAT issued and authenticated for account ' . $principal['account_id']);

$account = $principal['account_id'];
$book = mcp_coloring_create($account, '3f2b1c0e-9d8a-4b7c-a6e5-4d3c2b1a0f9e', fake_create_request());
step('3. created ' . $book['book_id'] . ' "' . $book['title'] . '" (' . $book['drawings_total'] . ' drawings, state ' . $book['state'] . ')');

$quote = mcp_coloring_quote($account, $book['book_id'], $book['plan_revision']);
step('4. quote ' . $quote['quote_id'] . ': cost ' . $quote['cost'] . ' (' . $quote['message'] . ')');

$started = mcp_coloring_start($account, $book['book_id'], $quote['quote_id'], $book['plan_revision']);
step('5. started, state ' . $started['state'] . ', charged ' . $started['charged']);

if (!fake_run_worker_until_ready()) {
    fwrite(STDERR, "the engine worker did not finish the book\n");
    exit(1);
}
$status = mcp_coloring_status($account, $book['book_id'])['payload'];
step('6. worker finished: ' . $status['state'] . ', ' . $status['drawings_done'] . '/' . $status['drawings_total'] . ' drawings, cover ready ' . var_export($status['cover_ready'], true));

$export = mcp_prepare_coloring_pdf($account, $book['book_id']);
step('7. prepare_coloring_pdf: ' . $export['artifact_id'] . ' state ' . $export['state']);
mcp_coloring_export_worker_run();
$export = mcp_get_coloring_pdf($account, $book['book_id'], $export['artifact_id']);
$download = mcp_coloring_export_download_file($account, $export['artifact_id']);
if ($export['state'] !== 'ready' || $download === null || !str_starts_with((string) file_get_contents($download['file'], false, null, 0, 5), '%PDF-')) {
    fwrite(STDERR, "the interior PDF was not produced\n");
    exit(1);
}

$out = __DIR__ . '/output';
if (!is_dir($out)) mkdir($out, 0775, true);
$target = $out . '/offline-example.pdf';
copy($download['file'], $target);
step('8. get_coloring_pdf: state ' . $export['state'] . ', ' . $export['file_size'] . ' bytes');
echo 'PDF: ', realpath($target), "\n";
