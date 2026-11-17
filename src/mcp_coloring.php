<?php

declare(strict_types=1);

/* The coloring tool handlers. Generation itself is the engine's job (coloring_worker, coloring_cover, coloring_book);
   these functions validate, scope every read to one account_id, and hand the work to the engine. */


use Mcp\Schema\Content\ImageContent;
use Mcp\Schema\Content\TextContent;
use Mcp\Schema\Result\CallToolResult;

function mcp_coloring_schema_available(?PDO $pdo = null): bool
{
    $pdo ??= mcp_db();
    $statement = $pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
        AND name IN ('mcp_coloring_books', 'mcp_coloring_quotes')");
    return (int) $statement->fetchColumn() === 2;
}

function mcp_coloring_cover_revision(array $project): string
{
    $path = (string) ($project['cover_path'] ?? '');
    $validPath = preg_match('#^coloring/cover-[a-f0-9]{24}\\.jpg$#D', $path) === 1;
    $file = mcp_coloring_data_directory() . '/' . $path;
    $hash = $validPath && is_file($file) && !is_link($file) ? hash_file('sha256', $file) : 'missing';
    return 'colorrev_' . substr(hash('sha256', implode("\n", [(string) ($project['id'] ?? 0),
        $path, (string) ($project['updated_at'] ?? ''), (string) ($hash ?: 'missing')])), 0, 24);
}

function mcp_coloring_cover_jpeg(string $bytes): string
{
    $png = mcp_custom_cover_png($bytes, MCP_CUSTOM_COLORING_COVER_MAX_RATIO);
    $image = @imagecreatefromstring($png);
    if ($image === false) throw new McpPlanError('INVALID_IMAGE', 'The cover image could not be decoded.');
    ob_start();
    $saved = imagejpeg($image, null, 90);
    $jpeg = ob_get_clean();
    if ($saved !== true || !is_string($jpeg) || $jpeg === '' || strlen($jpeg) > MCP_CUSTOM_COVER_MAX_BYTES) {
        throw new McpPlanError('INVALID_IMAGE', 'The cover image could not be safely prepared.');
    }
    return $jpeg;
}

/** Measure source-image detail after the exact crop used by the KDP front panel. */
function mcp_coloring_cover_source_quality(string $imageBytes): array
{
    $empty = ['cover_source_width_px' => null, 'cover_source_height_px' => null,
        'cover_source_ppi_x' => null, 'cover_source_ppi_y' => null,
        'cover_source_meets_300ppi' => null,
        'cover_source_resolution_note' => 'The cover detail could not be verified. Do not treat the wrap as KDP-ready; inspect the image before printing.'];
    $info = @getimagesizefromstring($imageBytes);
    if (!is_array($info) || (int) ($info[0] ?? 0) < 1 || (int) ($info[1] ?? 0) < 1) return $empty;
    $width = (int) $info[0];
    $height = (int) $info[1];
    $panelWidth = 8.625;
    $panelHeight = 11.25;
    $panelRatio = $panelWidth / $panelHeight;
    $cropWidth = $width;
    $cropHeight = $height;
    if ($width / $height < $panelRatio) {
        $cropHeight = max(1, min($height, (int) round($width / $panelRatio)));
    } elseif ($width / $height > $panelRatio) {
        $cropWidth = max(1, min($width, (int) round($height * $panelRatio)));
    }
    $ppiX = $cropWidth / $panelWidth;
    $ppiY = $cropHeight / $panelHeight;
    $meets = $ppiX >= 300.0 && $ppiY >= 300.0;
    $note = $meets
        ? 'The selected source artwork is at least 300 PPI after the wrap-panel crop. Check all other KDP cover requirements and use KDP Previewer; this is not an approval guarantee.'
        : sprintf('This cover is %d × %d px after crop (%.1f × %.1f PPI). It does not meet KDP’s published 300-DPI image minimum and may be flagged or rejected; do not submit it as KDP-ready. You can still print it yourself, but it may look soft or pixelated at this size, so check a proof. PDF resampling does not restore detail.',
            $cropWidth, $cropHeight, $ppiX, $ppiY);
    return ['cover_source_width_px' => $width, 'cover_source_height_px' => $height,
        'cover_source_ppi_x' => round($ppiX, 1), 'cover_source_ppi_y' => round($ppiY, 1),
        'cover_source_meets_300ppi' => $meets, 'cover_source_resolution_note' => $note];
}

function mcp_coloring_cover_result_with_quality(array $result, string $jpeg): array
{
    $quality = mcp_coloring_cover_source_quality($jpeg);
    $result['message'] = trim((string) ($result['message'] ?? '') . ' ' . $quality['cover_source_resolution_note']);
    return $result + $quality;
}

function mcp_apply_custom_coloring_cover(string $accountId, string $bookToken, array $file,
    string $expectedCoverRevision, ?PDO $pdo = null): array
{
    if (!is_string($file['file_id'] ?? null) || trim($file['file_id']) === '' || strlen($file['file_id']) > 255
        || !is_string($file['download_url'] ?? null) || strlen($file['download_url']) > 4096
        || preg_match('/^colorrev_[a-f0-9]{24}$/D', $expectedCoverRevision) !== 1) {
        throw new McpPlanError('VALIDATION_ERROR', 'A current coloring-book cover revision and image file are required.');
    }
    $project = mcp_coloring_owned($accountId, $bookToken, $pdo);
    if ($project === null || (string) $project['status'] !== 'ready' || (string) $project['cover_status'] !== 'done') {
        throw new McpPlanError('NOT_AVAILABLE', 'The coloring book must be complete before replacing its cover.');
    }
    if (!hash_equals(mcp_coloring_cover_revision($project), $expectedCoverRevision)) {
        throw new McpPlanError('REVISION_CONFLICT', 'The cover changed. Refresh the coloring-book viewer before applying this image.');
    }
    $jpeg = mcp_coloring_cover_jpeg(mcp_chatgpt_image_bytes($file['download_url']));
    $result = mcp_commit_custom_coloring_cover($accountId, $bookToken, $jpeg, $expectedCoverRevision, $pdo);
    return mcp_coloring_cover_result_with_quality($result, $jpeg);
}

function mcp_commit_custom_coloring_cover(string $accountId, string $bookToken, string $jpeg,
    string $expectedCoverRevision, ?PDO $pdo = null): array
{
    if (!mcp_account_id_valid($accountId) || $jpeg === '' || strlen($jpeg) > MCP_CUSTOM_COVER_MAX_BYTES
        || preg_match('/^colorrev_[a-f0-9]{24}$/D', $expectedCoverRevision) !== 1) {
        throw new McpPlanError('VALIDATION_ERROR', 'A current cover revision and valid image are required.');
    }
    mcp_content_safety_assert_image($jpeg);
    $pdo ??= mcp_db();
    $sourceProject = mcp_coloring_owned($accountId, $bookToken, $pdo);
    if ($sourceProject === null || (string) $sourceProject['status'] !== 'ready'
        || !hash_equals(mcp_coloring_cover_revision($sourceProject), $expectedCoverRevision)) {
        throw new McpPlanError('REVISION_CONFLICT', 'The coloring book or cover changed before the image could be applied.');
    }
    $directory = mcp_coloring_data_directory() . '/coloring';
    if (is_link($directory) || (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory))) {
        throw new RuntimeException('Coloring-book cover storage is unavailable.');
    }
    $filename = 'cover-' . bin2hex(random_bytes(12)) . '.jpg';
    $relative = 'coloring/' . $filename;
    $final = $directory . '/' . $filename;
    $temporary = $directory . '/.' . bin2hex(random_bytes(16)) . '.tmp';
    if (file_put_contents($temporary, $jpeg, LOCK_EX) !== strlen($jpeg)
        || !chmod($temporary, 0640) || !rename($temporary, $final)) {
        @unlink($temporary);
        throw new RuntimeException('The ChatGPT cover could not be stored.');
    }
    $outline = null;
    try {
        // Do provider work before the transaction, then publish both files with the revision check.
        $outline = coloring_save_cover_outline($jpeg, $sourceProject);
        $pdo->exec('BEGIN IMMEDIATE');
        $project = mcp_coloring_owned($accountId, $bookToken, $pdo);
        if ($project === null || (string) $project['status'] !== 'ready' || (string) $project['cover_status'] !== 'done'
            || !hash_equals(mcp_coloring_cover_revision($project), $expectedCoverRevision)) {
            throw new McpPlanError('REVISION_CONFLICT', 'The coloring book or cover changed before the image could be applied.');
        }
        $update = $pdo->prepare("UPDATE coloring_projects SET cover_path=?,cover_outline_path=?,kdp_metadata_json=NULL,cover_status='done',updated_at=datetime('now')
            WHERE id=? AND status='ready' AND cover_path=?");
        $update->execute([$relative, $outline, (int) $project['id'], (string) $project['cover_path']]);
        if ($update->rowCount() !== 1) throw new McpPlanError('REVISION_CONFLICT', 'The coloring book changed before the cover could be applied.');
        mcp_db_immediate_commit($pdo);
        $updated = mcp_coloring_owned($accountId, $bookToken, $pdo);
        return ['book_id' => $bookToken, 'state' => 'ready', 'source' => 'chatgpt_image',
            'cover_revision' => mcp_coloring_cover_revision($updated),
            'message' => 'Your supplied cover is selected unchanged. A matching uncoloured line-art version was generated for the interior using the engine image provider.'];
    } catch (Throwable $exception) {
        mcp_db_immediate_rollback($pdo);
        @unlink($final);
        if ($outline !== null) @unlink(coloring_outline_data_directory() . '/' . $outline);
        throw $exception;
    }
}

/** The coloring tools are on unless MCP_COLORING_ENABLED=0 (a kill switch) or the schema is missing. */
function mcp_coloring_enabled(?PDO $pdo = null): bool
{
    return trim((string) getenv('MCP_COLORING_ENABLED')) !== '0' && mcp_coloring_schema_available($pdo);
}

/** @return array<string,mixed> */
function mcp_coloring_plan_validate(array $request): array
{
    mcp_plan_require_keys($request, ['idea', 'style', 'audience', 'age_band', 'mood', 'occasion',
        'character_desc', 'page_count', 'plan'], 'coloring book');
    $idea = mcp_plan_text($request['idea'], 500, 'idea');
    $style = mcp_plan_text($request['style'], 80, 'style');
    $audience = mcp_plan_text($request['audience'], 40, 'audience');
    $characterDesc = mcp_plan_text($request['character_desc'], 200, 'character_desc', false);
    $optionalCategory = static function (mixed $value, string $field): ?string {
        return $value === null ? null : mcp_plan_text($value, 80, $field, false);
    };
    if (mb_strlen(trim($idea)) < 20) throw new McpPlanError('VALIDATION_ERROR', 'The coloring-book idea must be at least 20 characters.');
    if (!is_int($request['page_count']) || !isset(coloring_page_options()[$request['page_count']])) {
        throw new McpPlanError('VALIDATION_ERROR', 'Choose a supported coloring-book size: 16, 24, or 30 drawings.');
    }
    $categoryInput = ['audience' => $audience, 'age_band' => $optionalCategory($request['age_band'], 'age_band'),
        'mood' => $optionalCategory($request['mood'], 'mood'), 'occasion' => $optionalCategory($request['occasion'], 'occasion')];
    try {
        $base = coloring_validate(['idea' => $idea, 'style' => $style,
            'recurring' => trim($characterDesc) !== '',
            'character_desc' => $characterDesc, 'page_count' => (string) $request['page_count']]
            + $categoryInput);
    } catch (InvalidArgumentException $exception) {
        throw new McpPlanError('VALIDATION_ERROR', $exception->getMessage());
    }
    $plan = $request['plan'];
    if (!is_array($plan) || array_is_list($plan)) throw new McpPlanError('VALIDATION_ERROR', 'plan must be an object.');
    mcp_plan_require_keys($plan, ['title', 'style_sheet', 'cover', 'scenes'], 'plan');
    $title = mcp_plan_text($plan['title'], 160, 'title');
    $styleSheet = mcp_plan_text($plan['style_sheet'], 500, 'style_sheet', false);
    if (!is_array($plan['cover']) || array_is_list($plan['cover'])) throw new McpPlanError('VALIDATION_ERROR', 'cover must be an object.');
    mcp_plan_require_keys($plan['cover'], ['title_lines', 'theme', 'background'], 'cover');
    $lines = $plan['cover']['title_lines'];
    if (!is_array($lines) || !array_is_list($lines) || count($lines) < 1 || count($lines) > 3) {
        throw new McpPlanError('VALIDATION_ERROR', 'Cover title_lines must contain one to three lines.');
    }
    $titleLines = [];
    foreach ($lines as $line) $titleLines[] = mcp_plan_text($line, 32, 'cover title line');
    $cover = ['title_lines' => $titleLines,
        'theme' => mcp_plan_text($plan['cover']['theme'], 300, 'cover theme'),
        'background' => mcp_plan_text($plan['cover']['background'], 200, 'cover background')];
    if (!is_array($plan['scenes']) || !array_is_list($plan['scenes'])
        || count($plan['scenes']) !== $request['page_count']) {
        throw new McpPlanError('VALIDATION_ERROR', 'Provide exactly one scene for every selected drawing.');
    }
    $scenes = [];
    foreach ($plan['scenes'] as $index => $scene) {
        if (!is_array($scene) || array_is_list($scene)) throw new McpPlanError('VALIDATION_ERROR', 'Each scene must be an object.');
        mcp_plan_require_keys($scene, ['id', 'main', 'objects', 'setting', 'description'], 'scene');
        if (!is_int($scene['id']) || $scene['id'] !== $index + 1) {
            throw new McpPlanError('VALIDATION_ERROR', 'Scene IDs must be sequential, starting at 1.');
        }
        $scenes[] = ['id' => $scene['id'], 'main' => mcp_plan_text($scene['main'], 160, 'scene main subject'),
            'objects' => mcp_plan_text($scene['objects'], 300, 'scene objects'),
            'setting' => mcp_plan_text($scene['setting'], 200, 'scene setting'),
            'description' => mcp_plan_text($scene['description'], 500, 'scene description')];
    }
    return ['values' => $base, 'plan' => ['title' => $title, 'style_sheet' => $styleSheet,
        'cover' => $cover, 'scenes' => $scenes]];
}

function mcp_coloring_project_hash(array $project): string
{
    $snapshot = ['idea' => (string) $project['idea'], 'style' => (string) $project['style'],
        'audience' => (string) $project['audience'], 'age_band' => $project['age_band'],
        'mood' => $project['mood'], 'occasion' => $project['occasion'],
        'character_desc' => (string) $project['character_desc'], 'page_count' => coloring_project_pages($project),
        'plan' => json_decode((string) $project['plan_json'], true, flags: JSON_THROW_ON_ERROR)];
    return hash('sha256', json_encode(mcp_plan_hash_value($snapshot), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
}

/** Resolve a public opaque ID only inside the authenticated account. */
function mcp_coloring_owned(string $accountId, string $bookToken, ?PDO $pdo = null): ?array
{
    if (!mcp_account_id_valid($accountId) || preg_match('/^cb_[a-f0-9]{24}$/D', $bookToken) !== 1) return null;
    $pdo ??= mcp_db();
    // m.* first, then c.*: the engine row wins on shared names (id), the mapping row supplies account_id and book_token.
    $statement = $pdo->prepare('SELECT m.*, c.* FROM mcp_coloring_books m
        JOIN coloring_projects c ON c.id = m.project_id
        WHERE m.account_id = ? AND m.book_token = ?');
    $statement->execute([$accountId, $bookToken]);
    return $statement->fetch(PDO::FETCH_ASSOC) ?: null;
}

/** Persist a ChatGPT-authored plan. The UUID command can safely be retried after an uncertain MCP response. */
function mcp_coloring_create(string $accountId, string $commandId, array $request, ?PDO $pdo = null): array
{
    if (!mcp_account_id_valid($accountId)) throw new McpPlanError('NOT_AVAILABLE', 'The connected account is not available.');
    mcp_plan_command_id($commandId);
    $hash = hash('sha256', json_encode(mcp_plan_hash_value($request), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
    $pdo ??= mcp_db();

    // Resolve uncertain retries before moderation so a committed command remains replayable.
    $existing = $pdo->prepare('SELECT request_hash, book_token FROM mcp_coloring_books WHERE account_id = ? AND create_command_id = ?');
    $existing->execute([$accountId, $commandId]);
    $row = $existing->fetch(PDO::FETCH_ASSOC);
    if (is_array($row)) {
        if (!hash_equals((string) $row['request_hash'], $hash)) {
            throw new McpPlanError('COMMAND_CONFLICT', 'That command ID was already used with different coloring-book content.');
        }
        $project = mcp_coloring_owned($accountId, (string) $row['book_token'], $pdo);
        if ($project === null) throw new McpPlanError('NOT_AVAILABLE', 'That coloring book is no longer available.');
        return mcp_coloring_project_summary($project);
    }
    $canonical = mcp_coloring_plan_validate($request);
    mcp_content_safety_assert_suitable($canonical, 'input');

    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $existing = $pdo->prepare('SELECT request_hash, book_token FROM mcp_coloring_books WHERE account_id = ? AND create_command_id = ?');
        $existing->execute([$accountId, $commandId]);
        $row = $existing->fetch(PDO::FETCH_ASSOC);
        if (is_array($row)) {
            if (!hash_equals((string) $row['request_hash'], $hash)) {
                throw new McpPlanError('COMMAND_CONFLICT', 'That command ID was already used with different coloring-book content.');
            }
            $project = mcp_coloring_owned($accountId, (string) $row['book_token'], $pdo);
            if ($project === null) throw new McpPlanError('NOT_AVAILABLE', 'That coloring book is no longer available.');
            mcp_db_immediate_commit($pdo);
            return mcp_coloring_project_summary($project);
        }
        $projectId = coloring_create_project($accountId, $canonical['values']);
        $plan = ['title' => $canonical['plan']['title'], 'style_sheet' => $canonical['plan']['style_sheet'],
            'cover' => $canonical['plan']['cover'], 'scenes' => $canonical['plan']['scenes']];
        $planJson = json_encode($plan, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $pdo->prepare("UPDATE coloring_projects SET plan_json = ?, title = ?, status = 'planned', updated_at = datetime('now') WHERE id = ?")
            ->execute([$planJson, $plan['title'], $projectId]);
        $bookToken = 'cb_' . bin2hex(random_bytes(12));
        $project = coloring_project($projectId);
        if ($project === null) throw new RuntimeException('Coloring project disappeared while saving its MCP plan.');
        $pdo->prepare('INSERT INTO mcp_coloring_books
            (book_token, account_id, project_id, create_command_id, request_hash, current_revision, current_plan_hash)
            VALUES (?, ?, ?, ?, ?, 1, ?)')->execute([$bookToken, $accountId, $projectId, $commandId, $hash, mcp_coloring_project_hash($project)]);
        $project = mcp_coloring_owned($accountId, $bookToken, $pdo);
        mcp_db_immediate_commit($pdo);
        return mcp_coloring_project_summary($project);
    } catch (Throwable $exception) {
        mcp_db_immediate_rollback($pdo);
        throw $exception;
    }
}

/** What the host's quote_cost hook sees: the account, the book and its size. No engine or billing internals. */
function mcp_coloring_cost_context(string $accountId, array $project): array
{
    return ['account_id' => $accountId, 'book_token' => (string) $project['book_token'],
        'title' => (string) $project['title'], 'drawings_total' => coloring_project_pages($project),
        'plan_revision' => (int) $project['current_revision']];
}

function mcp_coloring_project_summary(array $project): array
{
    $plan = json_decode((string) ($project['plan_json'] ?? ''), true) ?: [];
    return ['book_id' => (string) $project['book_token'], 'title' => (string) $project['title'],
        'plan_revision' => (int) $project['current_revision'], 'state' => (string) $project['status'],
        'drawings_total' => count($plan['scenes'] ?? []),
        'next_action' => ['kind' => 'quote', 'label' => 'Review the quote before starting generation.']];
}

/** @return array{books:list<array<string,mixed>>} */
function mcp_coloring_list(string $accountId, ?PDO $pdo = null): array
{
    $pdo ??= mcp_db();
    $statement = $pdo->prepare('SELECT m.book_token, c.title, c.status, c.plan_json, c.pages_json,
        c.cover_status, c.cover_path FROM mcp_coloring_books m
        JOIN coloring_projects c ON c.id = m.project_id
        WHERE m.account_id = ? ORDER BY m.id DESC LIMIT 20');
    $statement->execute([$accountId]);
    $books = [];
    foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $project) {
        $progress = coloring_worker_status($project);
        $books[] = ['book_id' => (string) $project['book_token'], 'title' => (string) $project['title'],
            'state' => $progress['status'], 'stage' => $progress['stage'],
            'drawings_done' => $progress['pages_done'], 'drawings_total' => $progress['pages_total'],
            'cover_ready' => $progress['cover']];
    }
    return ['books' => $books];
}

/** @return array{payload:array<string,mixed>,images:list<array{label:string,image:ImageContent}>} */
function mcp_coloring_status(string $accountId, string $bookToken, int $offset = 0, int $limit = 4): array
{
    if ($offset < 0 || $offset > 30 || $limit < 1 || $limit > 4) {
        throw new McpPlanError('VALIDATION_ERROR', 'Use an image offset from 0 to 30 and an image limit from 1 to 4.');
    }
    $project = mcp_coloring_owned($accountId, $bookToken);
    if ($project === null) throw new McpPlanError('NOT_AVAILABLE', 'That coloring book is not available to this account.');
    $plan = json_decode((string) ($project['plan_json'] ?? ''), true) ?: [];
    $pages = json_decode((string) ($project['pages_json'] ?? '[]'), true) ?: [];
    $pagesById = [];
    foreach ($pages as $page) if (($page['status'] ?? '') === 'done') $pagesById[(int) $page['scene_id']] = $page;
    $total = count($plan['scenes'] ?? []) ?: coloring_project_pages($project);
    $progress = coloring_worker_status($project);
    $items = [];
    foreach ($plan['scenes'] ?? [] as $scene) {
        $id = (int) ($scene['id'] ?? 0);
        $page = $pagesById[$id] ?? null;
        $items[] = ['drawing' => $id, 'description' => (string) ($scene['description'] ?? ''),
            'state' => $page === null ? 'pending' : 'ready'];
    }
    $readyItems = array_values(array_filter($items, static fn(array $item): bool => $item['state'] === 'ready'));
    $selectedItems = array_slice($readyItems, $offset, $limit);
    $images = [];
    $artwork = [];
    foreach ($selectedItems as $item) {
        $page = $pagesById[$item['drawing']];
        $image = mcp_coloring_thumbnail((string) $page['path']);
        if ($image !== null) {
            $artwork[] = $image;
            $images[] = ['label' => 'Drawing ' . $item['drawing'] . ': ' . $item['description'],
                'image' => ImageContent::fromString($image, 'image/jpeg')];
        }
    }
    $outlineIncluded = false;
    if ($offset === 0 && coloring_has_cover_outline($project)) {
        $outline = mcp_coloring_thumbnail($project['cover_outline_path']);
        if ($outline !== null) {
            $artwork[] = $outline;
            array_unshift($images, ['label' => 'Cover coloring page: ' . (string) $project['title'],
                'image' => ImageContent::fromString($outline, 'image/jpeg')]);
            $outlineIncluded = true;
        }
    }
    $coverIncluded = false;
    $coverPath = (string) ($project['cover_path'] ?? '');
    if ($offset === 0 && $coverPath !== '' && $project['cover_status'] === 'done') {
        $cover = mcp_coloring_thumbnail($coverPath);
        if ($cover !== null) {
            $artwork[] = $cover;
            array_unshift($images, ['label' => 'Coloring-book cover: ' . (string) $project['title'],
                'image' => ImageContent::fromString($cover, 'image/jpeg')]);
            $coverIncluded = true;
        }
    }
    /* Offset zero may contain both opening pages plus the four requested drawing previews.
       Keep the safety endpoint's five-image ceiling and screen every returned image in bounded batches. */
    foreach (array_chunk($artwork, 5) as $safetyBatch) {
        mcp_content_safety_assert_images($safetyBatch);
    }
    $payload = ['book_id' => $bookToken, 'title' => (string) $project['title'], 'state' => $progress['status'],
        'stage' => $progress['stage'], 'drawings_done' => $progress['pages_done'], 'drawings_total' => $total,
        'cover_ready' => $progress['cover'], 'stalled' => $progress['stalled'], 'waiting_to_retry' => $progress['waiting'],
        'drawings' => $items, 'images_offset' => $offset, 'images_returned' => count($images) - ($coverIncluded ? 1 : 0) - ($outlineIncluded ? 1 : 0),
        'cover_outline_included' => $outlineIncluded,
        'more_images' => $offset + count($selectedItems) < count($readyItems), 'cover_included' => $coverIncluded,
        'cover_revision' => mcp_coloring_cover_revision($project),
        'note' => 'Each following labeled image is actual generated artwork from this owned project. Status reads do not advance generation.'];
    return ['payload' => $payload, 'images' => $images];
}

function mcp_coloring_thumbnail(string $relativePath): ?string
{
    if (preg_match('#^coloring/(?:cover-[a-f0-9]{24}|[a-f0-9]{32})\.(?:png|jpg)$#D', $relativePath) !== 1
        || !function_exists('imagecreatefromstring') || !function_exists('imagejpeg')) return null;
    $path = mcp_coloring_data_directory() . '/' . $relativePath;
    $bytes = @file_get_contents($path);
    if (!is_string($bytes)) return null;
    $source = @imagecreatefromstring($bytes);
    if ($source === false) return null;
    $width = imagesx($source); $height = imagesy($source);
    if ($width < 1 || $height < 1 || $width > 10000 || $height > 10000) { unset($source); return null; }
    $scale = min(768 / $width, 1024 / $height, 1);
    $thumb = imagescale($source, max(1, (int) round($width * $scale)), max(1, (int) round($height * $scale)));
    unset($source);
    if ($thumb === false) return null;
    ob_start(); imagejpeg($thumb, null, 82); $result = (string) ob_get_clean(); unset($thumb);
    return $result !== '' ? $result : null;
}

function mcp_coloring_data_directory(): string
{
    return isset($GLOBALS['mcp_coloring_data_directory']) && is_string($GLOBALS['mcp_coloring_data_directory'])
        ? $GLOBALS['mcp_coloring_data_directory'] : application_data_directory();
}

function mcp_coloring_result(array $payload, array $images = []): CallToolResult
{
    $content = [new TextContent(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))];
    foreach ($images as $item) {
        if (!is_array($item) || !isset($item['label'], $item['image']) || !$item['image'] instanceof ImageContent) continue;
        $content[] = new TextContent((string) $item['label']);
        $content[] = $item['image'];
    }
    return new CallToolResult($content, structuredContent: $payload);
}
