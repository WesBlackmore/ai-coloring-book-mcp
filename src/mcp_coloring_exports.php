<?php

declare(strict_types=1);

const MCP_COLORING_EXPORT_MAX_ATTEMPTS = 3;
const MCP_EXPORT_TTL_SECONDS = 86400;
const MCP_COLORING_EXPORT_BOOK_PDF = 'coloring_book_pdf';
const MCP_COLORING_EXPORT_KDP_WRAP = 'kdp_cover_wrap';

/** Backoff for a retry after a render failure, in seconds: exponential, 60 s floor, 1 h cap. */
function mcp_export_retry_backoff_seconds(int $attempts): int
{
    return min(3600, 60 * (2 ** max(0, $attempts - 1)));
}

/** Private artifact directory under the data dir: owner-only, never a symlink, with a deny-all guard file. */
function mcp_export_root(): string
{
    $root = application_data_directory() . '/mcp_artifacts';
    if (is_link($root)) throw new RuntimeException('Unsafe MCP artifact directory.');
    if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
        throw new RuntimeException('MCP artifact directory is unavailable.');
    }
    if ((fileperms($root) & 0077) !== 0) throw new RuntimeException('MCP artifact permissions are unsafe.');
    $guard = $root . '/.htaccess';
    if (!is_file($guard) && file_put_contents($guard, "Require all denied\n", LOCK_EX) === false) {
        throw new RuntimeException('MCP artifact directory guard is unavailable.');
    }
    if (trim((string) file_get_contents($guard)) !== 'Require all denied') {
        throw new RuntimeException('MCP artifact directory guard is unsafe.');
    }
    return $root;
}

function mcp_coloring_export_schema_available(?PDO $pdo = null): bool
{
    return ($pdo ?? mcp_db())->query("SELECT 1 FROM sqlite_master WHERE type = 'table'
        AND name = 'mcp_coloring_export_artifacts'")->fetchColumn() !== false;
}

function mcp_coloring_export_root(): string
{
    $root = mcp_export_root() . '/coloring';
    if (is_link($root) || (!is_dir($root) && !mkdir($root, 0700) && !is_dir($root))) {
        throw new RuntimeException('Coloring PDF artifact storage is unavailable.');
    }
    if ((fileperms($root) & 0077) !== 0) throw new RuntimeException('Coloring PDF artifact permissions are unsafe.');
    $guard = $root . '/.htaccess';
    if (!is_file($guard) && file_put_contents($guard, "Require all denied\n", LOCK_EX) === false) {
        throw new RuntimeException('Coloring PDF artifact guard is unavailable.');
    }
    if (trim((string) file_get_contents($guard)) !== 'Require all denied') {
        throw new RuntimeException('Coloring PDF artifact guard is unsafe.');
    }
    return $root;
}

/** A fingerprint of everything that changes the rendered bytes: engine renderers, this file, dompdf lock, title font. */
function mcp_coloring_export_renderer_version(): string
{
    $engine = mcp_engine_path();
    $files = [$engine . '/src/coloring_book.php', $engine . '/src/coloring_cover.php', __FILE__,
        $engine . '/composer.lock', $engine . '/public/fonts/BricolageGrotesque-650.ttf'];
    $hashes = [];
    foreach ($files as $file) {
        $hash = is_file($file) ? hash_file('sha256', $file) : false;
        if (!is_string($hash)) throw new RuntimeException('Coloring PDF renderer version is unavailable.');
        $hashes[] = basename($file) . ':' . $hash;
    }
    return 'php-coloring-pdf/v2:' . hash('sha256', implode("\n", $hashes));
}

function mcp_coloring_export_asset_path(string $relative): string
{
    if (preg_match('#^coloring/(?:cover-[a-f0-9]{24}\\.jpg|[a-f0-9]{32}\\.png)$#D', $relative) !== 1) {
        throw new RuntimeException('Coloring PDF contains an invalid image path.');
    }
    $dataDir = mcp_coloring_data_directory();
    if (is_link($dataDir . '/coloring') || is_link($dataDir . '/' . $relative)) {
        throw new RuntimeException('Coloring PDF artwork storage is unsafe.');
    }
    $root = realpath($dataDir . '/coloring');
    $path = realpath($dataDir . '/' . $relative);
    if ($root === false || $path === false || !str_starts_with($path, $root . DIRECTORY_SEPARATOR)
        || !is_file($path) || is_link($path)) {
        throw new RuntimeException('Coloring PDF artwork is unavailable.');
    }
    return $path;
}

/** Snapshot all rendered inputs and their hashes; never leave source files mutable under a queued artifact. */
function mcp_coloring_export_snapshot(array $project, string $exportType = MCP_COLORING_EXPORT_BOOK_PDF): array
{
    if (!in_array($exportType, [MCP_COLORING_EXPORT_BOOK_PDF, MCP_COLORING_EXPORT_KDP_WRAP], true)) {
        throw new InvalidArgumentException('Unsupported coloring export type.');
    }
    if ($exportType === MCP_COLORING_EXPORT_KDP_WRAP) {
        $coverPath = (string) ($project['cover_path'] ?? '');
        $coverFile = mcp_coloring_export_asset_path($coverPath);
        $coverHash = hash_file('sha256', $coverFile);
        if (!is_string($coverHash)) throw new RuntimeException('Coloring cover hash is unavailable.');
        $plan = json_decode((string) ($project['plan_json'] ?? ''), true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($plan) || !is_array($plan['scenes'] ?? null) || $plan['scenes'] === []) {
            throw new McpPlanError('NOT_AVAILABLE', 'The coloring-book print dimensions are not available yet.');
        }
        $wrapProject = [];
        foreach (['id','title','audience','page_count','plan_json','cover_path','cover_outline_path','trim'] as $key) {
            $wrapProject[$key] = $project[$key] ?? null;
        }
        return ['snapshot' => ['project' => $wrapProject, 'assets' => [$coverPath => $coverHash]],
            'cover_hash' => $coverHash];
    }
    $pages = json_decode((string) ($project['pages_json'] ?? ''), true, flags: JSON_THROW_ON_ERROR);
    $plan = json_decode((string) ($project['plan_json'] ?? ''), true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($pages) || !is_array($plan) || !is_array($plan['scenes'] ?? null)
        || count($pages) !== count($plan['scenes']) || $pages === []) {
        throw new McpPlanError('NOT_AVAILABLE', 'The completed coloring-book pages are not available yet.');
    }
    // Preserve the saved page order, as the website renderer does.
    $assets = [];
    foreach ($pages as $page) {
        if (($page['status'] ?? '') !== 'done' || !is_string($page['path'] ?? null)) {
            throw new McpPlanError('NOT_AVAILABLE', 'The completed coloring-book pages are not available yet.');
        }
        $path = $page['path'];
        $file = mcp_coloring_export_asset_path($path);
        $hash = hash_file('sha256', $file);
        if (!is_string($hash)) throw new RuntimeException('Coloring drawing hash is unavailable.');
        $assets[$path] = $hash;
    }
    $coverPath = (string) ($project['cover_path'] ?? '');
    $coverFile = mcp_coloring_export_asset_path($coverPath);
    $coverHash = hash_file('sha256', $coverFile);
    if (!is_string($coverHash)) throw new RuntimeException('Coloring cover hash is unavailable.');
    $assets[$coverPath] = $coverHash;
    if (coloring_has_cover_outline($project)) {
        $outlinePath = $project['cover_outline_path'];
        $hash = hash_file('sha256', mcp_coloring_export_asset_path($outlinePath));
        if (!is_string($hash)) throw new RuntimeException('Cover coloring page hash is unavailable.');
        $assets[$outlinePath] = $hash;
    }
    $snapshot = ['project' => [
        'id' => (int) $project['id'],
        'title' => (string) $project['title'], 'audience' => (string) $project['audience'],
        'status' => (string) $project['status'], 'cover_status' => (string) $project['cover_status'],
        'cover_path' => $coverPath, 'plan_json' => (string) $project['plan_json'],
        'cover_outline_path' => $project['cover_outline_path'] ?? null,
        'trim' => $project['trim'] ?? 'portrait', 'captions' => $project['captions'] ?? 0,
        'pages_json' => json_encode($pages, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
    ], 'assets' => $assets];
    return ['snapshot' => $snapshot, 'cover_hash' => $coverHash];
}

function mcp_coloring_export_record(string $accountId, string $bookToken, string $artifactId, PDO $pdo): ?array
{
    if (!mcp_account_id_valid($accountId) || preg_match('/^cb_[a-f0-9]{24}$/D', $bookToken) !== 1
        || preg_match('/^art_[a-f0-9]{24}$/D', $artifactId) !== 1) return null;
    $query = $pdo->prepare('SELECT * FROM mcp_coloring_export_artifacts
        WHERE account_id = ? AND book_token = ? AND artifact_id = ?');
    $query->execute([$accountId, $bookToken, $artifactId]);
    $row = $query->fetch(PDO::FETCH_ASSOC);
    return is_array($row) ? $row : null;
}

function mcp_coloring_export_file_is_valid(array $row): bool
{
    if ((string) ($row['state'] ?? '') !== 'ready' || $row['expires_at'] === null
        || (string) $row['expires_at'] <= gmdate('Y-m-d H:i:s')
        || preg_match('/^art_[a-f0-9]{24}\\.pdf$/D', (string) ($row['private_name'] ?? '')) !== 1) return false;
    $file = mcp_coloring_export_root() . '/' . $row['private_name'];
    return is_file($file) && !is_link($file) && filesize($file) === (int) $row['file_size']
        && hash_equals((string) $row['file_sha256'], (string) hash_file('sha256', $file));
}

function mcp_coloring_export_current_key(string $exportType, array $captured, string $renderer): array
{
    $snapshotJson = json_encode($captured['snapshot'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
    $contentHash = hash('sha256', $snapshotJson);
    $coverHash = (string) $captured['cover_hash'];
    $renderKey = hash('sha256', implode("\n", [$exportType, $contentHash, $coverHash, $renderer]));
    return ['snapshot_json' => $snapshotJson, 'content_hash' => $contentHash,
        'cover_hash' => $coverHash, 'render_key' => $renderKey];
}

/** Report detail in the selected source image before any print-size resampling. */
function mcp_coloring_export_source_quality(array $row): array
{
    if ((string) ($row['export_type'] ?? '') !== MCP_COLORING_EXPORT_KDP_WRAP) return [];
    $empty = ['cover_source_width_px' => null, 'cover_source_height_px' => null,
        'cover_source_ppi_x' => null, 'cover_source_ppi_y' => null,
        'cover_source_meets_300ppi' => null,
        'cover_source_resolution_note' => 'The cover detail could not be verified. Do not treat the wrap as KDP-ready; inspect the image before printing.'];
    try {
        $snapshot = json_decode((string) ($row['snapshot_json'] ?? ''), true, flags: JSON_THROW_ON_ERROR);
        $relative = (string) ($snapshot['project']['cover_path'] ?? '');
        if ($relative === '') return $empty;
        $bytes = file_get_contents(mcp_coloring_export_asset_path($relative));
        if (!is_string($bytes) || $bytes === '') return $empty;
        return mcp_coloring_cover_source_quality($bytes);
    } catch (Throwable) {
        return $empty;
    }
}

function mcp_coloring_export_matches_current(array $row, array $project): bool
{
    $exportType = (string) (($row['export_type'] ?? '') ?: MCP_COLORING_EXPORT_BOOK_PDF);
    if (!in_array($exportType, [MCP_COLORING_EXPORT_BOOK_PDF, MCP_COLORING_EXPORT_KDP_WRAP], true)) return false;
    try {
        $captured = mcp_coloring_export_snapshot($project, $exportType);
        $key = mcp_coloring_export_current_key($exportType, $captured, mcp_coloring_export_renderer_version());
        return hash_equals((string) ($row['render_key'] ?? ''), $key['render_key']);
    } catch (Throwable) {
        return false;
    }
}

/** Retire a stale immutable snapshot so neither users nor workers can reuse it. */
function mcp_coloring_export_mark_stale(array $row, PDO $pdo): void
{
    $name = (string) ($row['private_name'] ?? '');
    if ($name !== '' && preg_match('/^art_[a-f0-9]{24}\.pdf$/D', $name) !== 1) {
        throw new RuntimeException('Invalid stored coloring PDF filename.');
    }
    if ($name !== '') {
        $path = mcp_coloring_export_root() . '/' . $name;
        if (is_link($path) || (is_file($path) && !unlink($path))) {
            throw new RuntimeException('Could not retire a stale coloring PDF.');
        }
    }
    // `stale` is an API presentation state; the durable table intentionally
    // keeps its established lifecycle enum, where `expired` is terminal.
    $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state='expired',private_name=NULL,file_sha256=NULL,
        file_size=NULL,expires_at=NULL,retry_at=NULL,lease_token=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP
        WHERE id=?")->execute([(int) $row['id']]);
}

function mcp_coloring_export_state(array $row, bool $isCurrent = true): array
{
    $ready = $isCurrent && mcp_coloring_export_file_is_valid($row);
    $state = !$isCurrent ? 'stale' : ($ready ? 'ready' : ((string) $row['state'] === 'ready' ? 'expired' : (string) $row['state']));
    $exportType = (string) ($row['export_type'] ?? '') ?: MCP_COLORING_EXPORT_BOOK_PDF;
    if (!in_array($exportType, [MCP_COLORING_EXPORT_BOOK_PDF, MCP_COLORING_EXPORT_KDP_WRAP], true)) {
        throw new RuntimeException('Unknown coloring export type.');
    }
    return ['artifact_id' => (string) $row['artifact_id'], 'book_id' => (string) $row['book_token'],
        'format' => 'pdf', 'export_type' => $exportType, 'state' => $state, 'content_hash' => (string) $row['content_hash'],
        'cover_hash' => (string) $row['cover_hash'], 'renderer_version' => (string) $row['renderer_version'],
        'is_current' => $isCurrent,
        'message' => $isCurrent ? 'This export matches the current book snapshot.'
            : 'This saved export is for an older book or cover revision. Prepare a new export without an artifact ID.',
        'retry_at' => $row['retry_at'], 'expires_at' => $ready ? $row['expires_at'] : null,
        'file_size' => $ready ? (int) $row['file_size'] : null,
        'file_sha256' => $ready ? (string) $row['file_sha256'] : null,
        'download_url' => $ready ? mcp_public_base_url() . '/download?artifact=' . rawurlencode((string) $row['artifact_id']) : null]
        + mcp_coloring_export_source_quality($row);
}

function mcp_prepare_coloring_export(string $accountId, string $bookToken, string $exportType,
    ?string $artifactId = null, ?PDO $pdo = null): array
{
    $pdo ??= mcp_db();
    if (!in_array($exportType, [MCP_COLORING_EXPORT_BOOK_PDF, MCP_COLORING_EXPORT_KDP_WRAP], true)
        || preg_match('/^cb_[a-f0-9]{24}$/D', $bookToken) !== 1
        || ($artifactId !== null && preg_match('/^art_[a-f0-9]{24}$/D', $artifactId) !== 1)) {
        throw new McpPlanError('VALIDATION_ERROR', 'A valid coloring-book and optional artifact ID are required.');
    }
    $renderer = mcp_coloring_export_renderer_version();
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $project = mcp_coloring_owned($accountId, $bookToken, $pdo);
        if ($project === null || (string) $project['status'] !== 'ready'
            || (string) $project['cover_status'] !== 'done') {
            throw new McpPlanError('NOT_AVAILABLE', 'The coloring book must be complete, with a cover, before PDF export.');
        }
        $captured = mcp_coloring_export_snapshot($project, $exportType);
        $key = mcp_coloring_export_current_key($exportType, $captured, $renderer);
        if ($artifactId !== null) {
            $row = mcp_coloring_export_record($accountId, $bookToken, $artifactId, $pdo);
            $storedType = is_array($row) ? ((string) ($row['export_type'] ?? '') ?: MCP_COLORING_EXPORT_BOOK_PDF) : '';
            if ($row === null || $storedType !== $exportType || (string) $row['renderer_version'] !== $renderer) {
                throw new McpPlanError('NOT_AVAILABLE', 'That coloring PDF export is not available. Prepare a current export instead.');
            }
            if (!hash_equals((string) ($row['render_key'] ?? ''), $key['render_key'])) {
                mcp_coloring_export_mark_stale($row, $pdo);
                $pdo->exec('COMMIT');
                $row['state'] = 'stale';
                return mcp_coloring_export_state($row, false);
            }
        } else {
            $find = $pdo->prepare('SELECT * FROM mcp_coloring_export_artifacts WHERE project_id = ? AND render_key = ?');
            $find->execute([(int) $project['id'], $key['render_key']]);
            $row = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                $artifactId = 'art_' . bin2hex(random_bytes(12));
                $pdo->prepare("INSERT INTO mcp_coloring_export_artifacts
                    (artifact_id,account_id,project_id,book_token,render_key,content_hash,cover_hash,renderer_version,
                     snapshot_json,state,attempts,export_type)
                    VALUES (?,?,?,?,?,?,?,?,?,'queued',0,?)")
                    ->execute([$artifactId, $accountId, (int) $project['id'], $bookToken, $key['render_key'],
                        $key['content_hash'], $key['cover_hash'], $renderer, $key['snapshot_json'], $exportType]);
                $row = mcp_coloring_export_record($accountId, $bookToken, $artifactId, $pdo);
                if ($row === null) throw new RuntimeException('Coloring PDF export was not saved.');
            }
        }
        if ((string) $row['state'] === 'ready' && !mcp_coloring_export_file_is_valid($row)) {
            $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state='expired',private_name=NULL,
                file_sha256=NULL,file_size=NULL,expires_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?")
                ->execute([(int) $row['id']]);
            $row['state'] = 'expired';
        }
        if ((string) $row['state'] === 'expired') {
            $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state='queued',attempts=0,retry_at=NULL,
                lease_token=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?")
                ->execute([(int) $row['id']]);
        }
        $fresh = mcp_coloring_export_record($accountId, $bookToken, (string) $row['artifact_id'], $pdo);
        if ($fresh === null) throw new RuntimeException('Coloring PDF export state was not readable.');
        $pdo->exec('COMMIT');
        return mcp_coloring_export_state($fresh, true);
    } catch (Throwable $exception) {
        mcp_db_immediate_rollback($pdo);
        throw $exception;
    }
}

function mcp_prepare_coloring_pdf(string $accountId, string $bookToken, ?string $artifactId = null, ?PDO $pdo = null): array
{
    return mcp_prepare_coloring_export($accountId, $bookToken, MCP_COLORING_EXPORT_BOOK_PDF, $artifactId, $pdo);
}

function mcp_prepare_coloring_cover_wrap(string $accountId, string $bookToken, ?string $artifactId = null, ?PDO $pdo = null): array
{
    return mcp_prepare_coloring_export($accountId, $bookToken, MCP_COLORING_EXPORT_KDP_WRAP, $artifactId, $pdo);
}

function mcp_get_coloring_export(string $accountId, string $bookToken, string $artifactId, string $exportType, ?PDO $pdo = null): array
{
    $pdo ??= mcp_db();
    if (mcp_coloring_owned($accountId, $bookToken, $pdo) === null) {
        throw new McpPlanError('NOT_AVAILABLE', 'That coloring book is not available to this account.');
    }
    $row = mcp_coloring_export_record($accountId, $bookToken, $artifactId, $pdo);
    if ($row === null) throw new McpPlanError('NOT_AVAILABLE', 'That PDF is not available to this account.');
    $storedType = (string) (($row['export_type'] ?? '') ?: MCP_COLORING_EXPORT_BOOK_PDF);
    if ($storedType !== $exportType) throw new McpPlanError('NOT_AVAILABLE', 'That PDF is not available to this account.');
    $project = mcp_coloring_owned($accountId, $bookToken, $pdo);
    return mcp_coloring_export_state($row, $project !== null && mcp_coloring_export_matches_current($row, $project));
}

function mcp_get_coloring_pdf(string $accountId, string $bookToken, string $artifactId, ?PDO $pdo = null): array
{
    return mcp_get_coloring_export($accountId, $bookToken, $artifactId, MCP_COLORING_EXPORT_BOOK_PDF, $pdo);
}

function mcp_get_coloring_cover_wrap(string $accountId, string $bookToken, string $artifactId, ?PDO $pdo = null): array
{
    return mcp_get_coloring_export($accountId, $bookToken, $artifactId, MCP_COLORING_EXPORT_KDP_WRAP, $pdo);
}

function mcp_coloring_export_download_file(string $accountId, string $artifactId, ?PDO $pdo = null): ?array
{
    if (!mcp_account_id_valid($accountId) || preg_match('/^art_[a-f0-9]{24}$/D', $artifactId) !== 1) return null;
    $pdo ??= mcp_db();
    $query = $pdo->prepare('SELECT * FROM mcp_coloring_export_artifacts WHERE account_id = ? AND artifact_id = ?');
    $query->execute([$accountId, $artifactId]);
    $row = $query->fetch(PDO::FETCH_ASSOC);
    $project = is_array($row) ? mcp_coloring_owned($accountId, (string) $row['book_token'], $pdo) : null;
    if (!is_array($row) || $project === null || !mcp_coloring_export_matches_current($row, $project)
        || !mcp_coloring_export_file_is_valid($row)) return null;
    return ['file' => mcp_coloring_export_root() . '/' . $row['private_name'], 'size' => (int) $row['file_size'],
        'format' => 'pdf', 'export_type' => (string) (($row['export_type'] ?? '') ?: MCP_COLORING_EXPORT_BOOK_PDF),
        'artifact_id' => $artifactId];
}

/** Expire a bounded number of private coloring PDFs using the existing maintenance schedule. */
function mcp_coloring_export_expire(PDO $pdo, int $limit = 100, ?int $now = null): array
{
    if ($limit < 1 || $limit > 1000) throw new InvalidArgumentException('Invalid coloring PDF expiry limit.');
    if (!mcp_coloring_export_schema_available($pdo)) return ['deleted' => 0, 'limit_reached' => false, 'failed' => 0];
    $clock = gmdate('Y-m-d H:i:s', $now ?? time());
    $query = $pdo->prepare("SELECT id, artifact_id FROM mcp_coloring_export_artifacts
        WHERE state='ready' AND expires_at <= ? ORDER BY expires_at,id LIMIT " . ($limit + 1));
    $query->execute([$clock]);
    $rows = $query->fetchAll(PDO::FETCH_ASSOC);
    $result = ['deleted' => 0, 'limit_reached' => count($rows) > $limit, 'failed' => 0];
    foreach (array_slice($rows, 0, $limit) as $row) {
        try {
            $pdo->exec('BEGIN IMMEDIATE');
            $fresh = $pdo->prepare("SELECT private_name FROM mcp_coloring_export_artifacts
                WHERE id=? AND state='ready' AND expires_at <= ?");
            $fresh->execute([(int) $row['id'], $clock]);
            $name = $fresh->fetchColumn();
            if (!is_string($name)) { $pdo->exec('COMMIT'); continue; }
            if (preg_match('/^art_[a-f0-9]{24}\\.pdf$/D', $name) !== 1) {
                throw new RuntimeException('Invalid stored coloring PDF filename.');
            }
            $path = mcp_coloring_export_root() . '/' . $name;
            $existed = is_file($path);
            if (is_link($path) || ($existed && !unlink($path))) {
                throw new RuntimeException('Could not remove expired coloring PDF.');
            }
            $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state='expired',private_name=NULL,
                file_sha256=NULL,file_size=NULL,expires_at=NULL,updated_at=CURRENT_TIMESTAMP
                WHERE id=? AND state='ready' AND expires_at <= ?")->execute([(int) $row['id'], $clock]);
            $pdo->exec('COMMIT');
            if ($existed) $result['deleted']++;
        } catch (Throwable) {
            try { $pdo->exec('ROLLBACK'); } catch (Throwable) {}
            $result['failed']++;
        }
    }
    return $result;
}

function mcp_coloring_export_worker_claim(PDO $pdo, int $now): ?array
{
    $clock = gmdate('Y-m-d H:i:s', $now);
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $retry = gmdate('Y-m-d H:i:s', $now + 60);
        $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state=CASE WHEN attempts>=? THEN 'failed' ELSE 'retry_wait' END,
            retry_at=CASE WHEN attempts>=? THEN NULL ELSE ? END,lease_token=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP
            WHERE state='rendering' AND lease_until<?")
            ->execute([MCP_COLORING_EXPORT_MAX_ATTEMPTS, MCP_COLORING_EXPORT_MAX_ATTEMPTS, $retry, $clock]);
        $query = $pdo->prepare("SELECT * FROM mcp_coloring_export_artifacts WHERE attempts<?
            AND (state='queued' OR (state='retry_wait' AND retry_at<=?)) ORDER BY id LIMIT 20");
        $query->execute([MCP_COLORING_EXPORT_MAX_ATTEMPTS, $clock]);
        $rows = $query->fetchAll(PDO::FETCH_ASSOC);
        $row = null;
        foreach ($rows as $candidate) {
            $project = mcp_coloring_owned((string) $candidate['account_id'], (string) $candidate['book_token'], $pdo);
            if ($project === null || !mcp_coloring_export_matches_current($candidate, $project)) {
                mcp_coloring_export_mark_stale($candidate, $pdo);
                continue;
            }
            $row = $candidate;
            break;
        }
        if (!is_array($row)) { $pdo->exec('COMMIT'); return null; }
        $lease = bin2hex(random_bytes(16));
        $until = gmdate('Y-m-d H:i:s', $now + 300);
        $update = $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state='rendering',attempts=attempts+1,
            lease_token=?,lease_until=?,retry_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=? AND state IN ('queued','retry_wait')");
        $update->execute([$lease, $until, (int) $row['id']]);
        if ($update->rowCount() !== 1) throw new RuntimeException('Coloring PDF lease was lost.');
        $row['lease_token'] = $lease;
        $row['lease_until'] = $until;
        $row['attempts'] = (int) $row['attempts'] + 1;
        $pdo->exec('COMMIT');
        return $row;
    } catch (Throwable $exception) {
        mcp_db_immediate_rollback($pdo);
        throw $exception;
    }
}

function mcp_coloring_export_worker_render(array $row, string $tempPath): array
{
    $snapshotJson = (string) $row['snapshot_json'];
    if (!hash_equals((string) $row['content_hash'], hash('sha256', $snapshotJson))
        || (string) $row['renderer_version'] !== mcp_coloring_export_renderer_version()) {
        throw new RuntimeException('Coloring PDF snapshot or renderer changed.');
    }
    $snapshot = json_decode($snapshotJson, true, flags: JSON_THROW_ON_ERROR);
    $project = $snapshot['project'] ?? null;
    $assets = $snapshot['assets'] ?? null;
    if (!is_array($project) || !is_array($assets) || !isset($assets[$project['cover_path'] ?? ''])
        || !hash_equals((string) $row['cover_hash'], (string) ($assets[$project['cover_path']] ?? ''))) {
        throw new RuntimeException('Coloring PDF cover snapshot is invalid.');
    }
    $exportType = (string) (($row['export_type'] ?? '') ?: MCP_COLORING_EXPORT_BOOK_PDF);
    if (!in_array($exportType, [MCP_COLORING_EXPORT_BOOK_PDF, MCP_COLORING_EXPORT_KDP_WRAP], true)) {
        throw new RuntimeException('Unknown coloring export type.');
    }
    foreach ($assets as $relative => $hash) {
        $actual = hash_file('sha256', mcp_coloring_export_asset_path((string) $relative));
        if (!is_string($actual) || !hash_equals((string) $hash, $actual)) {
            throw new RuntimeException('Coloring artwork changed after PDF preparation.');
        }
    }
    $bytes = $exportType === MCP_COLORING_EXPORT_KDP_WRAP
        ? coloring_cover_wrap_pdf_from_bytes($project,
            (string) file_get_contents(mcp_coloring_export_asset_path((string) $project['cover_path'])))
        : coloring_export_pdf($project, true);
    if ($bytes === '' || !str_starts_with($bytes, '%PDF-') || strlen($bytes) > 100 * 1024 * 1024
        || file_put_contents($tempPath, $bytes, LOCK_EX) !== strlen($bytes)) {
        throw new RuntimeException('Coloring PDF artifact is invalid.');
    }
    $hash = hash_file('sha256', $tempPath);
    if (!is_string($hash)) throw new RuntimeException('Coloring PDF checksum is unavailable.');
    return ['size' => strlen($bytes), 'sha256' => $hash];
}

function mcp_coloring_export_worker_publish(PDO $pdo, array $row, string $tempPath, array $file, int $now): void
{
    $publishedPath = null;
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $query = $pdo->prepare("SELECT state,lease_token,lease_until FROM mcp_coloring_export_artifacts WHERE id=?");
        $query->execute([(int) $row['id']]);
        $current = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($current) || $current['state'] !== 'rendering'
            || !hash_equals((string) $current['lease_token'], (string) $row['lease_token'])
            || (string) $current['lease_until'] < gmdate('Y-m-d H:i:s', $now)) {
            throw new RuntimeException('Coloring PDF lease expired before publish.');
        }
        $name = (string) $row['artifact_id'] . '.pdf';
        $destination = mcp_coloring_export_root() . '/' . $name;
        if (!rename($tempPath, $destination)) throw new RuntimeException('Could not publish coloring PDF.');
        $publishedPath = $destination;
        chmod($destination, 0600);
        $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state='ready',private_name=?,file_sha256=?,file_size=?,
            expires_at=?,lease_token=NULL,lease_until=NULL,retry_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=? AND lease_token=?")
            ->execute([$name, $file['sha256'], $file['size'], gmdate('Y-m-d H:i:s', $now + MCP_EXPORT_TTL_SECONDS),
                (int) $row['id'], $row['lease_token']]);
        $pdo->exec('COMMIT');
    } catch (Throwable $exception) {
        mcp_db_immediate_rollback($pdo);
        if (is_string($publishedPath) && is_file($publishedPath) && !is_link($publishedPath)) @unlink($publishedPath);
        throw $exception;
    }
}

function mcp_coloring_export_worker_fail(PDO $pdo, array $row, int $now): void
{
    $attempts = (int) $row['attempts'];
    $state = $attempts >= MCP_COLORING_EXPORT_MAX_ATTEMPTS ? 'failed' : 'retry_wait';
    $retryAt = $state === 'failed' ? null : gmdate('Y-m-d H:i:s', $now + mcp_export_retry_backoff_seconds($attempts));
    $pdo->prepare("UPDATE mcp_coloring_export_artifacts SET state=?,retry_at=?,lease_token=NULL,lease_until=NULL,
        updated_at=CURRENT_TIMESTAMP WHERE id=? AND state='rendering' AND lease_token=?")
        ->execute([$state, $retryAt, (int) $row['id'], $row['lease_token']]);
}

/** A bounded side job: run it from cron or the worker loop (see examples/ and the README). */
function mcp_coloring_export_worker_run(?PDO $pdo = null, int $budget = 1, ?int $now = null): array
{
    $pdo ??= mcp_db();
    if ($budget < 1 || $budget > 4) throw new InvalidArgumentException('Invalid coloring PDF worker budget.');
    if (!mcp_coloring_export_schema_available($pdo)) return ['ready' => 0, 'retry_wait' => 0, 'failed' => 0];
    $now ??= time();
    $result = ['ready' => 0, 'retry_wait' => 0, 'failed' => 0];
    $oldUmask = umask(0077);
    try {
        for ($i = 0; $i < $budget; $i++) {
            $row = mcp_coloring_export_worker_claim($pdo, $now);
            if ($row === null) break;
            $temp = mcp_coloring_export_root() . '/' . $row['artifact_id'] . '.' . bin2hex(random_bytes(8)) . '.tmp';
            try {
                $file = mcp_coloring_export_worker_render($row, $temp);
                mcp_coloring_export_worker_publish($pdo, $row, $temp, $file, time());
                $result['ready']++;
            } catch (Throwable $exception) {
                error_log('ai-coloring-book-mcp coloring PDF failure: ' . get_class($exception));
                mcp_coloring_export_worker_fail($pdo, $row, time());
                $result[(int) $row['attempts'] >= MCP_COLORING_EXPORT_MAX_ATTEMPTS ? 'failed' : 'retry_wait']++;
            } finally {
                if (is_file($temp)) unlink($temp);
            }
        }
    } finally {
        umask($oldUmask);
    }
    return $result;
}
