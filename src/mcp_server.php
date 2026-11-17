<?php

declare(strict_types=1);

use Http\Discovery\Psr17Factory;
use Mcp\Schema\Content\TextContent;
use Mcp\Schema\Content\TextResourceContents;
use Mcp\Schema\Enum\ProtocolVersion;
use Mcp\Schema\Extension\Apps\McpApps;
use Mcp\Schema\Result\CallToolResult;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server;
use Mcp\Server\Session\FileSessionStore;
use Mcp\Server\Transport\Http\Middleware\CorsMiddleware;
use Mcp\Server\Transport\Http\Middleware\DnsRebindingProtectionMiddleware;
use Mcp\Server\Transport\StreamableHttpTransport;

// Resource URIs are host cache keys. Bump the version when widget behavior changes.
const MCP_COLORING_VIEWER_RESOURCE_URI = 'ui://ai-coloring-book-mcp/coloring-viewer/v1.html';

// Presentation and workflow guidance, not authorization: exact references remain in tool data.
const MCP_INSTRUCTIONS = 'Use authoritative book titles in user-facing replies, headings, progress reports, confirmations, image labels and suggested follow-up prompts. Keep identifiers internal: use exact book, artifact and revision identifiers for tool calls, not as ordinary user-facing labels. Never change or redact machine identifiers or returned download URLs; label download links by title and format. If only an identifier is known, retrieve the owned book title first; never invent a title. An identifier is never proof of ownership; every operation is account-scoped. Save the user-reviewed plan with create_coloring_book, review the quote_coloring_book result (cost, can_start, message), and call start_coloring_book only after the user explicitly confirms the displayed cost; a cost of 0 means the book is free. Never infer approval. Status reads never advance work. Use get_coloring_book to report truthful progress and show its returned image blocks as the actual book artwork; paginate using image_offset, and do not substitute or claim unseen artwork. Distinguish the complete coloring-book PDF (prepare_coloring_pdf) from the separate Amazon KDP paperback cover wrap (prepare_coloring_cover_wrap); check each with its matching get tool and only share a ready download link. When a coloring-cover tool returns cover_source_resolution_note, relay it plainly: below 300 PPI, the image does not meet KDP’s published minimum and may be flagged or rejected; a user may still print it personally, but it may look soft or pixelated. Never call a below-300-PPI wrap KDP-ready, and do not imply PDF resampling restores detail.';

function mcp_coloring_viewer_resource(string $uri = MCP_COLORING_VIEWER_RESOURCE_URI): TextResourceContents
{
    $path = MCP_PACKAGE_ROOT . '/resources/coloring-viewer.html';
    $html = file_get_contents($path);
    if (!is_string($html) || $html === '') {
        throw new RuntimeException('The MCP coloring viewer resource is unavailable.');
    }
    return new TextResourceContents($uri, McpApps::MIME_TYPE, $html,
        ['ui' => ['prefersBorder' => true, 'csp' => ['resourceDomains' => ['data:']]],
            'openai/widgetDescription' => 'Displays the authenticated coloring book status and real generated cover and drawing previews returned by this server.']);
}

/** Keep the first text block as complete JSON for existing text-only clients. */
/** @param array<string,mixed> $payload */
function mcp_read_result(array $payload, ?string $presentationGuidance = null): CallToolResult
{
    $content = [new TextContent(json_encode($payload,
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))];
    if ($presentationGuidance !== null) $content[] = new TextContent($presentationGuidance);
    return new CallToolResult($content, structuredContent: $payload);
}

function mcp_read_error(string $code, string $message): CallToolResult
{
    $payload = ['code' => $code, 'message' => $message, 'retryable' => false, 'next_action' => null];
    return new CallToolResult([new TextContent(json_encode($payload, JSON_THROW_ON_ERROR))], true,
        structuredContent: $payload);
}

/** @param callable():CallToolResult $callback */
function mcp_read_safe(callable $callback): CallToolResult
{
    try {
        return $callback();
    } catch (McpPlanError $exception) {
        return mcp_read_error($exception->errorCode, $exception->getMessage());
    } catch (InvalidArgumentException) {
        return mcp_read_error('VALIDATION_ERROR', 'Check the supplied arguments and try again.');
    } catch (Throwable $exception) {
        error_log('ai-coloring-book-mcp tool failure: ' . get_class($exception));
        return mcp_read_error('TEMPORARILY_UNAVAILABLE', 'This operation is temporarily unavailable.');
    }
}

/** The least-privilege scopes each tool needs. Anything unknown needs READ only. */
function mcp_tool_scope_map(): array
{
    $read = [MCP_PAT_READ_SCOPE];
    $write = [MCP_PAT_READ_SCOPE, MCP_PAT_WRITE_SCOPE];
    $export = [MCP_PAT_READ_SCOPE, MCP_PAT_EXPORT_SCOPE];
    return [
        'list_my_coloring_books' => $read, 'get_coloring_book' => $read,
        'create_coloring_book' => $write, 'quote_coloring_book' => $write,
        'start_coloring_book' => $write, 'apply_custom_coloring_cover' => $write,
        'prepare_coloring_pdf' => $export, 'get_coloring_pdf' => $export,
        'prepare_coloring_cover_wrap' => $export, 'get_coloring_cover_wrap' => $export,
    ];
}

function mcp_tool_required_scopes(string $toolName): array
{
    return mcp_tool_scope_map()[$toolName] ?? [MCP_PAT_READ_SCOPE];
}

/** @param list<string> $granted @return list<string> the scopes this tool needs that the credential lacks */
function mcp_missing_scopes(string $toolName, array $granted): array
{
    return array_values(array_diff(mcp_tool_required_scopes($toolName), $granted));
}

/**
 * The PHP SDK has no first-class tool securitySchemes field. Add OpenAI's per-tool auth extension to tools/list
 * responses while the OAuth module is enabled; authorization is still enforced by the endpoint and scopes.
 */
function mcp_oauth_attach_tool_security_schemes(string $responseBody, string $contentType = 'application/json'): ?string
{
    $adaptMessage = static function (string $json): ?string {
        $message = json_decode($json, true);
        if (!is_array($message) || !is_array($message['result'] ?? null)
            || !is_array($message['result']['tools'] ?? null)) return null;
        $scopeByTool = mcp_tool_scope_map();
        foreach ($message['result']['tools'] as &$tool) {
            if (!is_array($tool) || !is_string($tool['name'] ?? null)
                || !isset($scopeByTool[$tool['name']])) return null;
            // The SDK serializes an empty PHP array as JSON [] even though JSON Schema requires `properties`
            // to be an object, and ChatGPT's tool refresh rejects that. Normalize it here.
            if (is_array($tool['inputSchema'] ?? null)
                && ($tool['inputSchema']['properties'] ?? null) === []) {
                $tool['inputSchema']['properties'] = new stdClass();
            }
            $securitySchemes = [['type' => 'oauth2', 'scopes' => $scopeByTool[$tool['name']]]];
            $tool['securitySchemes'] = $securitySchemes;
            // OpenAI documents `_meta.securitySchemes` as a compatibility mirror.
            if (!is_array($tool['_meta'] ?? null)) $tool['_meta'] = [];
            $tool['_meta']['securitySchemes'] = $securitySchemes;
        }
        unset($tool);
        try {
            return json_encode($message, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (JsonException) { return null; }
    };
    if (str_contains(strtolower($contentType), 'application/json')) return $adaptMessage($responseBody);
    if (!str_contains(strtolower($contentType), 'text/event-stream')) return null;
    $adapted = false;
    $lines = preg_split('/(?<=\n)/', $responseBody) ?: [];
    foreach ($lines as &$line) {
        if (!str_starts_with($line, 'data:')) continue;
        $ending = str_ends_with($line, "\r\n") ? "\r\n" : (str_ends_with($line, "\n") ? "\n" : '');
        $data = substr($line, 5);
        if (str_starts_with($data, ' ')) $data = substr($data, 1);
        $data = rtrim($data, "\r\n");
        $replacement = $adaptMessage($data);
        if ($replacement !== null) {
            $line = 'data: ' . $replacement . $ending;
            $adapted = true;
        }
    }
    unset($line);
    return $adapted ? implode('', $lines) : null;
}

/** Build per-request handlers around an already authenticated account. Coloring tools only. */
function mcp_coloring_server(string $accountId, string $tokenId): Server
{
    $builder = Server::builder()
        ->setServerInfo('ai-coloring-book-mcp', '1.0.0', 'Create coloring books and KDP-ready PDF exports.')
        ->setInstructions(MCP_INSTRUCTIONS)
        ->setProtocolVersion(ProtocolVersion::V2025_06_18)
        ->withoutModernEra()
        ->setSession(new FileSessionStore(mcp_session_directory($tokenId), 3600))
        ->enableExtension(new McpApps());
    if (mcp_coloring_enabled()) {
        $builder = $builder->addResource(
            static fn (): TextResourceContents => mcp_coloring_viewer_resource(),
            MCP_COLORING_VIEWER_RESOURCE_URI,
            name: 'ai-coloring-book-viewer-v1',
            title: 'AI Coloring Book viewer',
            description: 'Displays authenticated coloring-book progress and actual generated artwork.',
            mimeType: McpApps::MIME_TYPE,
            meta: ['ui' => McpApps::resourceMarker()],
        );
        $builder = mcp_add_coloring_tools($builder, $accountId);
    }
    return $builder->build();
}

function mcp_add_coloring_tools($builder, string $accountId)
{
    $read = new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false);
    $write = new ToolAnnotations(readOnlyHint: false, destructiveHint: false, openWorldHint: false);
    $start = new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: false);
    $bookPattern = mcp_coloring_book_id_schema();
    $artifactPattern = ['type' => 'string', 'pattern' => '^art_[a-f0-9]{24}$'];
    $builder->addTool(
        static fn(): CallToolResult => mcp_read_safe(static fn(): CallToolResult => mcp_read_result(mcp_coloring_list($accountId))),
        name: 'list_my_coloring_books',
        description: 'List coloring books created through this MCP connection, with current generation progress. Present titles to the user; retain book_id internally for follow-up tools.',
        annotations: $read, inputSchema: ['type' => 'object', 'properties' => [], 'additionalProperties' => false],
        outputSchema: ['type' => 'object', 'properties' => ['books' => ['type' => 'array', 'items' => ['type' => 'object']]],
            'required' => ['books'], 'additionalProperties' => false]);
    $builder->addTool(
        static fn(string $book_id, int $image_offset = 0, int $image_limit = 4): CallToolResult => mcp_read_safe(
            static function () use ($accountId, $book_id, $image_offset, $image_limit): CallToolResult {
                $result = mcp_coloring_status($accountId, $book_id, $image_offset, $image_limit);
                return mcp_coloring_result($result['payload'], $result['images']);
            }),
        name: 'get_coloring_book',
        description: 'Read progress and inspect real generated artwork for an owned coloring book. Report its title and progress, not its internal book_id. The interactive viewer displays actual image blocks returned by this authenticated tool call. Returns up to four images (plus the cover on the first page); set image_offset to view later drawings. This read never advances generation.',
        annotations: $read,
        inputSchema: ['type' => 'object', 'properties' => ['book_id' => $bookPattern,
            'image_offset' => ['type' => 'integer', 'minimum' => 0, 'maximum' => 30],
            'image_limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 4]],
            'required' => ['book_id'], 'additionalProperties' => false],
        meta: ['ui' => ['resourceUri' => MCP_COLORING_VIEWER_RESOURCE_URI],
            'openai/outputTemplate' => MCP_COLORING_VIEWER_RESOURCE_URI,
            'openai/toolInvocation/invoking' => 'Loading coloring-book artwork…',
            'openai/toolInvocation/invoked' => 'Coloring-book artwork is ready to view.'],
        outputSchema: mcp_coloring_status_schema());
    $builder->addTool(
        static fn(string $create_command_id, array $idea_and_plan): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(mcp_coloring_create($accountId, $create_command_id, $idea_and_plan))),
        name: 'create_coloring_book',
        description: 'Save a complete coloring-book plan and scenes as a draft project. No images are generated and nothing is charged. Use a UUIDv4 create_command_id and reuse it unchanged if the result is uncertain. The user must review the plan and quote before generation.',
        annotations: $write,
        inputSchema: ['type' => 'object', 'properties' => ['create_command_id' => ['type' => 'string', 'format' => 'uuid'],
            'idea_and_plan' => mcp_coloring_plan_input_schema()],
            'required' => ['create_command_id', 'idea_and_plan'], 'additionalProperties' => false],
        outputSchema: mcp_coloring_summary_schema());
    $builder->addTool(
        static fn(string $book_id, int $plan_revision): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(mcp_coloring_quote($accountId, $book_id, $plan_revision))),
        name: 'quote_coloring_book',
        description: 'Quote the current plan. The cost comes from the host’s quote_cost hook and is 0 (free) when none is registered. This creates no images and reserves or charges nothing. Quote is valid for 15 minutes; review it with the user before calling start_coloring_book.',
        annotations: $write,
        inputSchema: ['type' => 'object', 'properties' => ['book_id' => $bookPattern, 'plan_revision' => ['type' => 'integer', 'minimum' => 1]],
            'required' => ['book_id', 'plan_revision'], 'additionalProperties' => false],
        outputSchema: mcp_coloring_quote_schema());
    $builder->addTool(
        static fn(string $book_id, string $quote_id, int $plan_revision): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(mcp_coloring_start($accountId, $book_id, $quote_id, $plan_revision))),
        name: 'start_coloring_book',
        description: 'Start image generation using the exact owned plan revision and unexpired quote. This runs the host’s charge hook (always approved when none is registered) and then queues generation; call only after the user explicitly confirms this plan and the quoted cost. If the charge is denied nothing is generated. The engine worker makes the images. Retry the same book and quote IDs after an uncertain response.',
        annotations: $start,
        inputSchema: ['type' => 'object', 'properties' => ['book_id' => $bookPattern,
            'quote_id' => ['type' => 'string', 'pattern' => '^cq_[a-f0-9]{24}$'],
            'plan_revision' => ['type' => 'integer', 'minimum' => 1]],
            'required' => ['book_id', 'quote_id', 'plan_revision'], 'additionalProperties' => false],
        outputSchema: mcp_coloring_start_schema());
    $fileSchema = ['type' => 'object', 'properties' => ['download_url' => ['type' => 'string'],
        'file_id' => ['type' => 'string'], 'mime_type' => ['type' => 'string'], 'file_name' => ['type' => 'string']],
        'required' => ['download_url', 'file_id'], 'additionalProperties' => false];
    $builder->addTool(
        static fn(string $book_id, array $image, string $expected_cover_revision): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(
                mcp_apply_custom_coloring_cover($accountId, $book_id, $image, $expected_cover_revision))),
        name: 'apply_custom_coloring_cover',
        title: 'Apply a ChatGPT-created coloring-book cover',
        description: 'Apply the exact image the user created with ChatGPT to their owned, completed coloring book. Use a portrait PNG, JPEG or WebP, at least 500 × 750 px, preferably close to the 8.625:11.25 front-panel ratio (about 0.767:1); the KDP wrap crops proportionally to fit. To retain 300 PPI across that full panel requires at least about 2588 × 3375 effective pixels after crop. ChatGPT image generation may ignore a requested pixel size; verify actual dimensions. The result reports source pixels and effective PPI after crop. If below 300 PPI, clearly tell the user this does not meet KDP’s published 300-DPI image minimum and may be flagged or rejected; do not present it as KDP-ready. Explain that they may still print it themselves, but it may look soft or pixelated and they should inspect a proof. PDF resampling does not restore detail. First call get_coloring_book and pass its current cover_revision. Only call after the user explicitly asks to apply the image. This preserves all drawings and is reversible by applying another cover. The uploaded original is kept as the selected cover and the engine image provider creates a matching uncoloured outline for the interior. After success, call get_coloring_book to confirm the cover, then offer prepare_coloring_pdf. The server sanitizes and revision-checks the image.',
        annotations: $start,
        inputSchema: ['type' => 'object', '$defs' => ['ChatGPTImageFile' => $fileSchema],
            'properties' => ['book_id' => $bookPattern, 'image' => ['$ref' => '#/$defs/ChatGPTImageFile'],
                'expected_cover_revision' => ['type' => 'string', 'pattern' => '^colorrev_[a-f0-9]{24}$']],
            'required' => ['book_id', 'image', 'expected_cover_revision'], 'additionalProperties' => false],
        meta: ['openai/fileParams' => ['image']],
        outputSchema: mcp_coloring_cover_result_schema());
    $export = new ToolAnnotations(readOnlyHint: false, destructiveHint: false, openWorldHint: false);
    $exportRead = new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false);
    $prepareInput = ['type' => 'object', 'properties' => ['book_id' => $bookPattern, 'artifact_id' => $artifactPattern],
        'required' => ['book_id'], 'additionalProperties' => false];
    $getInput = ['type' => 'object', 'properties' => ['book_id' => $bookPattern, 'artifact_id' => $artifactPattern],
        'required' => ['book_id', 'artifact_id'], 'additionalProperties' => false];
    $builder->addTool(
        static fn(string $book_id, ?string $artifact_id = null): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(mcp_prepare_coloring_pdf($accountId, $book_id, $artifact_id))),
        name: 'prepare_coloring_pdf',
        description: 'Prepare a complete coloring-book PDF with the selected full-colour cover, its matching uncoloured line-art page when available, overview sheets of the saved drawings, and the full-size drawings with blank backs. The full-colour cover fills the first PDF page edge-to-edge; there is no blank reverse after it. The cover-derived outline follows immediately on page two, fills that page edge-to-edge, and then has a blank reverse. Both cover pages are proportionally cropped to the selected trim; a low-resolution source may look soft when enlarged, and this does not restore detail. The first overview has a 4 × 4 grid and a count heading; later overview sheets use 4 × 5 grids. Generated drawing pages use a 2340 × 3120 px grid placed at exactly 300 effective PPI. The separate KDP cover-wrap tool reports its source-image PPI and any under-300 warning. Requires the owned coloring book to be complete and its cover ready. Uses a durable snapshot and the export worker; nothing is charged. When queued, report that it is preparing and call get_coloring_pdf to check. Show a download link only when state is ready and is_current is true. If an artifact is stale after a cover or book change, prepare again without artifact_id; never re-share its old link.',
        annotations: $export, inputSchema: $prepareInput, outputSchema: mcp_coloring_export_schema());
    $builder->addTool(
        static fn(string $book_id, ?string $artifact_id = null): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(mcp_prepare_coloring_cover_wrap($accountId, $book_id, $artifact_id))),
        name: 'prepare_coloring_cover_wrap',
        title: 'Prepare Amazon KDP coloring-book cover wrap',
        description: 'Prepare the separate, single-page Amazon KDP paperback cover-wrap PDF (back cover, calculated spine and front cover) for the owned, completed coloring book. This is not the complete coloring-book interior PDF. Uses the current selected cover, immutable snapshot and the export worker; nothing is charged. Reports source pixels and effective PPI after the wrap crop. If below 300 PPI, clearly tell the user this fails KDP’s published image-resolution minimum and may be flagged or rejected; do not describe the file as KDP-ready. They can still print it themselves, but it may look soft or pixelated; recommend checking a proof. Resampling does not restore detail. Dimensions follow the engine’s print-cover calculations; do not claim KDP acceptance, and recommend checking the final PDF with KDP’s Cover Calculator/Previewer. When queued, check with get_coloring_cover_wrap. Share a download link only when ready and is_current is true. Reuse artifact_id only to recover an expired export if it still matches the current book and cover; if stale, prepare again without artifact_id and never share the old link.',
        annotations: $export, inputSchema: $prepareInput, outputSchema: mcp_coloring_export_schema());
    $builder->addTool(
        static fn(string $book_id, string $artifact_id): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(mcp_get_coloring_cover_wrap($accountId, $book_id, $artifact_id))),
        name: 'get_coloring_cover_wrap',
        title: 'Check Amazon KDP cover-wrap PDF',
        description: 'Check the state of this account’s KDP coloring-book cover-wrap export. This is the separate print cover (back, spine and front), not the complete coloring-book PDF. Return its bearer-token-bound download URL only while the artifact is ready, unexpired, and is_current is true. Include source art dimensions, effective PPI, and the resolution note. When below 300 PPI, clearly say the file does not meet KDP’s published image-resolution minimum and may be flagged or rejected; it may still be printed personally but could look soft or pixelated. Do not treat resampling as restored detail or call it KDP-ready. If state is stale or is_current is false, do not use that download; call prepare_coloring_cover_wrap without artifact_id to generate a wrap for the current cover.',
        annotations: $exportRead, inputSchema: $getInput, outputSchema: mcp_coloring_export_schema());
    $builder->addTool(
        static fn(string $book_id, string $artifact_id): CallToolResult => mcp_read_safe(
            static fn(): CallToolResult => mcp_read_result(mcp_get_coloring_pdf($accountId, $book_id, $artifact_id))),
        name: 'get_coloring_pdf',
        description: 'Check the state of an owned coloring-book PDF export. Return its bearer-token-bound download URL only when ready, unexpired, and is_current is true. If stale, prepare a new export without artifact_id.',
        annotations: $exportRead, inputSchema: $getInput, outputSchema: mcp_coloring_export_schema());
    return $builder;
}

/** A private, filesystem-backed MCP protocol session is not a browser login. */
function mcp_session_directory(string $tokenId): string
{
    if (preg_match('/^[a-f0-9]{24}$/D', $tokenId) !== 1) {
        throw new RuntimeException('Invalid MCP session namespace.');
    }
    $root = application_data_directory() . '/mcp_sessions';
    if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
        throw new RuntimeException('MCP session store unavailable.');
    }
    $guard = $root . '/.htaccess';
    if (!is_file($guard) && file_put_contents($guard, "Require all denied\n", LOCK_EX) === false) {
        throw new RuntimeException('MCP session store guard unavailable.');
    }
    if (trim((string) file_get_contents($guard)) !== 'Require all denied') {
        throw new RuntimeException('MCP session store guard is unsafe.');
    }
    $path = $root . '/' . $tokenId;
    if (!is_dir($path) && !mkdir($path, 0700, true) && !is_dir($path)) {
        throw new RuntimeException('MCP session store unavailable.');
    }
    if (!is_writable($path) || (fileperms($root) & 0077) !== 0 || (fileperms($path) & 0077) !== 0) {
        throw new RuntimeException('MCP session store permissions are unsafe.');
    }
    return $path;
}

/** 200 allowed, 429 limited, 503 counter unavailable; keyed to the account, never to a shared proxy IP. */
function mcp_read_rate_limit_status(string $accountId): int
{
    $limit = max(1, (int) (getenv('MCP_RATE_LIMIT_PER_HOUR') ?: 240));
    $root = application_data_directory() . '/mcp_ratelimit';
    if (is_link($root)) return 503;
    if (!is_dir($root) && !@mkdir($root, 0700, true) && !is_dir($root)) return 503;
    if ((fileperms($root) & 0077) !== 0) return 503;
    $window = intdiv(time(), 3600);
    $windowDir = $root . '/' . $window;
    if (is_link($windowDir)) return 503;
    if (!is_dir($windowDir) && !@mkdir($windowDir, 0700) && !is_dir($windowDir)) return 503;
    if ((fileperms($windowDir) & 0077) !== 0) return 503;
    $path = $windowDir . '/' . hash('sha256', 'mcp-account:' . $accountId) . '.count';
    $file = @fopen($path, 'c+');
    if ($file === false) return 503;
    try {
        if (!flock($file, LOCK_EX)) return 503;
        $stored = trim((string) stream_get_contents($file));
        if ($stored !== '' && !ctype_digit($stored)) return 503;
        $count = (int) $stored + 1;
        rewind($file);
        if (!ftruncate($file, 0) || fwrite($file, (string) $count) === false) return 503;
        fflush($file);
        return $count <= $limit ? 200 : 429;
    } finally {
        flock($file, LOCK_UN);
        fclose($file);
    }
}

/** Treat only explicit web-SAPI HTTPS markers as secure (a TLS-terminating proxy must set HTTPS). */
function mcp_request_is_secure(): bool
{
    return in_array(strtolower(trim((string) ($_SERVER['HTTPS'] ?? ''))), ['on', '1'], true);
}

/** Hosts this server answers for: MCP_ALLOWED_HOSTS (comma list) plus the host of MCP_PUBLIC_BASE_URL, plus localhost. */
function mcp_allowed_hosts(): array
{
    $hosts = ['localhost', '127.0.0.1'];
    foreach (explode(',', (string) getenv('MCP_ALLOWED_HOSTS')) as $host) {
        $host = strtolower(trim($host));
        if ($host !== '') $hosts[] = $host;
    }
    $base = parse_url((string) getenv('MCP_PUBLIC_BASE_URL'), PHP_URL_HOST);
    if (is_string($base) && $base !== '') $hosts[] = strtolower($base);
    return array_values(array_unique($hosts));
}

/** Serve the official SDK over ordinary short PHP requests. No browser session is opened. */
function mcp_serve_http(): void
{
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    if (($_SERVER['HTTP_ORIGIN'] ?? '') !== '') {
        http_response_code(403);
        return;
    }
    $host = strtolower(explode(':', (string) ($_SERVER['HTTP_HOST'] ?? ''))[0]);
    $local = in_array($host, ['localhost', '127.0.0.1'], true);
    if (!in_array($host, mcp_allowed_hosts(), true) || (!$local && !mcp_request_is_secure())) {
        http_response_code(403);
        return;
    }
    // All operations work through short POST request/response exchanges; no persistent stream is needed.
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        header('Allow: POST');
        http_response_code(405);
        return;
    }
    if (isset($_SERVER['CONTENT_LENGTH']) && ctype_digit((string) $_SERVER['CONTENT_LENGTH'])
        && (int) $_SERVER['CONTENT_LENGTH'] > 1048576) {
        http_response_code(413);
        return;
    }
    $oauthEnabled = trim((string) getenv('MCP_OAUTH_ENABLED')) === '1';
    if ($oauthEnabled) require_once __DIR__ . '/oauth/http.php';
    $authorization = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    try {
        // PATs stay first-class. OAuth access tokens are an additional path when the OAuth module is enabled.
        $principal = mcp_pat_authenticate($authorization);
        if ($principal === null && $oauthEnabled) {
            if (preg_match('/^(?i:Bearer) ([A-Za-z0-9._~-]{1,8192})$/D', $authorization, $match)) {
                $principal = mcp_oauth_authenticate_access_token($match[1]);
            }
        }
    } catch (Throwable $exception) {
        error_log('ai-coloring-book-mcp authentication unavailable: ' . get_class($exception));
        http_response_code(503);
        return;
    }
    $anonymousDiscovery = false;
    $anonymousRequest = null;
    if ($principal === null && $oauthEnabled && $authorization === '') {
        // ChatGPT needs tool-level OAuth metadata before it can start account linking. Permit only protocol
        // setup and tools/list without credentials; never dispatch a tool anonymously.
        try {
            $factory = new Psr17Factory();
            $anonymousRequest = $factory->createServerRequestFromGlobals();
            $stream = $anonymousRequest->getBody();
            if ($stream->isSeekable()) $stream->rewind();
            $body = $stream->isSeekable() ? $stream->read(1048577) : '';
            if (strlen($body) > 1048576) {
                http_response_code(413);
                return;
            }
            $rpc = json_decode($body, true);
            $rpcMethod = is_array($rpc) ? ($rpc['method'] ?? null) : null;
            $rpcId = is_array($rpc) ? ($rpc['id'] ?? null) : null;
            $safeDiscoveryMethod = in_array($rpcMethod,
                ['initialize', 'notifications/initialized', 'ping', 'tools/list'], true);
            if ($rpcMethod === 'tools/call' && (is_string($rpcId) || is_int($rpcId))) {
                $challenge = 'Bearer resource_metadata="' . mcp_oauth_http_config()['resource_metadata']
                    . '", scope="' . MCP_PAT_READ_SCOPE . '"';
                $responseBody = json_encode(['jsonrpc' => '2.0', 'id' => $rpcId, 'result' => [
                    'content' => [['type' => 'text', 'text' => 'Connect your account to use this tool.']],
                    'isError' => true,
                    '_meta' => ['mcp/www_authenticate' => [$challenge]],
                ]], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                http_response_code(200);
                header('Content-Type: application/json');
                header('Content-Length: ' . strlen($responseBody));
                echo $responseBody;
                return;
            }
            $anonymousDiscovery = $safeDiscoveryMethod;
        } catch (Throwable $exception) {
            error_log('ai-coloring-book-mcp anonymous discovery failed: ' . get_class($exception));
        }
    }
    if ($principal === null && !$anonymousDiscovery) {
        $challenge = 'Bearer realm="AI Coloring Book MCP", scope="' . MCP_PAT_READ_SCOPE . '"';
        if ($oauthEnabled) {
            try {
                $oauthConfig = mcp_oauth_http_config();
                $challenge .= ', resource_metadata="' . $oauthConfig['resource_metadata'] . '"';
                if ($authorization !== '') {
                    $challenge .= ', error="invalid_token", error_description="Authentication is required or the token is invalid."';
                }
            } catch (Throwable) {
                // Do not make the PAT endpoint unavailable if OAuth config is incomplete.
            }
        }
        header('WWW-Authenticate: ' . $challenge);
        http_response_code(401);
        return;
    }
    if (!$anonymousDiscovery && !in_array(MCP_PAT_READ_SCOPE, $principal['scopes'], true)) {
        http_response_code(403);
        return;
    }
    $rateStatus = $anonymousDiscovery ? 200 : mcp_read_rate_limit_status($principal['account_id']);
    if ($rateStatus !== 200) {
        if ($rateStatus === 429) header('Retry-After: 3600');
        http_response_code($rateStatus);
        return;
    }
    $oldUmask = umask(0077);
    try {
        $factory = new Psr17Factory();
        $request = $anonymousRequest ?? $factory->createServerRequestFromGlobals();
        $requestBody = '';
        $requestStream = $request->getBody();
        if ($requestStream->isSeekable()) {
            $requestStream->rewind();
            $requestBody = $requestStream->getContents();
            $requestStream->rewind();
        }
        $rpcRequest = json_decode($requestBody, true);
        if (!$anonymousDiscovery && is_array($rpcRequest)
            && ($rpcRequest['method'] ?? null) === 'tools/call'
            && is_array($rpcRequest['params'] ?? null)
            && is_string($rpcRequest['params']['name'] ?? null)
            && (is_string($rpcRequest['id'] ?? null) || is_int($rpcRequest['id'] ?? null))) {
            $requiredScopes = mcp_tool_required_scopes($rpcRequest['params']['name']);
            $missingScopes = mcp_missing_scopes($rpcRequest['params']['name'], $principal['scopes']);
            if ($missingScopes !== []) {
                $message = 'This tool needs additional permission: '
                    . implode(' ', $requiredScopes) . '. Reconnect and grant that permission to continue.';
                $result = ['content' => [['type' => 'text', 'text' => $message]], 'isError' => true];
                if ($oauthEnabled && is_string($principal['grant_id'] ?? null)) {
                    $metadataUrl = mcp_oauth_http_config()['resource_metadata'];
                    $scope = implode(' ', $requiredScopes);
                    $challenge = 'Bearer resource_metadata="' . $metadataUrl
                        . '", error="insufficient_scope", error_description="Additional permission is required.", scope="'
                        . $scope . '"';
                    $result['_meta'] = ['mcp/www_authenticate' => [$challenge]];
                }
                $responseBody = json_encode(['jsonrpc' => '2.0', 'id' => $rpcRequest['id'],
                    'result' => $result], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                http_response_code(200);
                header('Content-Type: application/json');
                header('Content-Length: ' . strlen($responseBody));
                echo $responseBody;
                return;
            }
        }
        $server = mcp_coloring_server($anonymousDiscovery ? 'discovery' : $principal['account_id'],
            $anonymousDiscovery ? substr(hash('sha256', 'ai-coloring-book-mcp-oauth-discovery'), 0, 24) : $principal['token_id']);
        $transport = new StreamableHttpTransport($request,
            middleware: [new CorsMiddleware(), new DnsRebindingProtectionMiddleware([$host])],
            maxBodyBytes: 1048576);
        $response = $server->run($transport);
        if ($oauthEnabled && is_array($rpcRequest)
            && ($rpcRequest['method'] ?? null) === 'tools/list') {
            $responseStream = $response->getBody();
            if ($responseStream->isSeekable()) {
                $responseStream->rewind();
                $adaptedBody = mcp_oauth_attach_tool_security_schemes(
                    $responseStream->getContents(), $response->getHeaderLine('Content-Type'));
                $responseStream->rewind();
                if ($adaptedBody === null) { http_response_code(503); return; }
                $response = $response->withBody(\Nyholm\Psr7\Stream::create($adaptedBody))
                    ->withHeader('Content-Length', (string) strlen($adaptedBody));
            } else {
                http_response_code(503);
                return;
            }
        }
        http_response_code($response->getStatusCode());
        foreach ($response->getHeaders() as $name => $values) {
            if (strtolower($name) === 'set-cookie') continue;
            header($name . ': ' . implode(', ', $values));
        }
        header('Cache-Control: no-store');
        $body = $response->getBody();
        if ($body->isSeekable()) $body->rewind();
        echo $body->getContents();
    } catch (Throwable $exception) {
        error_log('ai-coloring-book-mcp transport failure: ' . get_class($exception));
        http_response_code(503);
    } finally {
        umask($oldUmask);
    }
}
