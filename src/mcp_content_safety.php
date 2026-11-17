<?php

declare(strict_types=1);

/*
 * Content suitability gate (OpenAI moderation), on by default.
 *
 * Text plans and image previews are screened before they are saved or returned. With a key set the gate is
 * fail-closed: a moderation outage blocks the call. With NO OPENAI_API_KEY the gate cannot run, so it is skipped
 * with a logged warning instead of failing a keyless install. Set MCP_CONTENT_SAFETY=0 to switch it off on purpose.
 * This is a policy filter, not a child-safety detector; known or suspected CSAM must never be sent to the
 * Moderation API.
 */

const MCP_CONTENT_SAFETY_MAX_CHARS = 20000;

/**
 * Whether a screening call can and should run. Test seams count as configured. A missing key skips the gate
 * (once-per-process warning); an explicit MCP_CONTENT_SAFETY=0 skips it silently.
 */
function mcp_content_safety_active(): bool
{
    if (trim((string) getenv('MCP_CONTENT_SAFETY')) === '0') return false;
    if (is_callable($GLOBALS['mcp_content_safety_provider'] ?? null)
        || is_callable($GLOBALS['mcp_content_safety_image_provider'] ?? null)
        || is_callable($GLOBALS['mcp_content_safety_transport'] ?? null)) return true;
    if (trim((string) getenv('OPENAI_API_KEY')) !== '') return true;
    static $warned = false;
    if (!$warned) {
        $warned = true;
        error_log('ai-coloring-book-mcp content gate: OPENAI_API_KEY is not set, moderation is SKIPPED. '
            . 'Set the key to screen plans and artwork.');
    }
    return false;
}

/** @return list<string> */
function mcp_content_safety_text_values(mixed $value): array
{
    if (is_string($value)) return [$value];
    if (!is_array($value)) return [];
    $texts = [];
    foreach ($value as $child) {
        array_push($texts, ...mcp_content_safety_text_values($child));
    }
    return $texts;
}

/** @return list<string> */
function mcp_content_safety_chunks(array $value): array
{
    $texts = array_values(array_filter(array_map('trim', mcp_content_safety_text_values($value)),
        static fn(string $text): bool => $text !== ''));
    $chunks = [];
    $chunk = '';
    foreach ($texts as $text) {
        while ($text !== '') {
            $separatorLength = $chunk === '' ? 0 : 1;
            $room = MCP_CONTENT_SAFETY_MAX_CHARS - mb_strlen($chunk) - $separatorLength;
            if ($room < 1) {
                $chunks[] = $chunk;
                $chunk = '';
                $room = MCP_CONTENT_SAFETY_MAX_CHARS;
            }
            $take = min($room, mb_strlen($text));
            $chunk .= ($chunk === '' ? '' : "\n") . mb_substr($text, 0, $take);
            $text = mb_substr($text, $take);
            if (mb_strlen($chunk) >= MCP_CONTENT_SAFETY_MAX_CHARS) {
                $chunks[] = $chunk;
                $chunk = '';
            }
        }
    }
    if ($chunk !== '') $chunks[] = $chunk;
    return $chunks;
}

/** @return array<string,mixed> Moderation result object. Throws on any unavailable/invalid response. */
function mcp_content_safety_moderate(string $text): array
{
    $testProvider = $GLOBALS['mcp_content_safety_provider'] ?? null;
    if (is_callable($testProvider)) {
        $result = $testProvider($text);
        if (!is_array($result)) throw new RuntimeException('MCP moderation returned an invalid test response.');
        return $result;
    }

    return mcp_content_safety_request($text);
}

/** Text or documented multimodal moderation input; never log the payload. */
function mcp_content_safety_request(string|array $input, int $timeoutMs = 10000): array
{
    $transport = $GLOBALS['mcp_content_safety_transport'] ?? null;
    if (is_callable($transport)) return $transport($input);
    $apiKey = trim((string) getenv('OPENAI_API_KEY'));
    if ($apiKey === '' || !function_exists('curl_init')) {
        error_log('ai-coloring-book-mcp moderation transport: configured=' . ($apiKey !== '' ? 'yes' : 'no')
            . ' curl=' . (function_exists('curl_init') ? 'yes' : 'no'));
        throw new RuntimeException('MCP moderation is not configured.');
    }
    $payload = json_encode([
        'model' => getenv('OPENAI_MODERATION_MODEL') ?: 'omni-moderation-latest',
        'input' => $input,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
    $handle = curl_init('https://api.openai.com/v1/moderations');
    if ($handle === false) throw new RuntimeException('MCP moderation could not start.');
    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => ['content-type: application/json', 'authorization: Bearer ' . $apiKey],
        CURLOPT_TIMEOUT_MS => $timeoutMs,
        CURLOPT_CONNECTTIMEOUT_MS => min(5000, $timeoutMs),
    ]);
    $response = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    if (!is_string($response) || $status !== 200) {
        $error = is_string($response) ? json_decode($response, true) : null;
        $code = preg_replace('/[^a-zA-Z0-9_-]/', '', (string) ($error['error']['code'] ?? 'none'));
        error_log('ai-coloring-book-mcp moderation transport: http=' . $status . ' curl_errno=' . curl_errno($handle)
            . ' code=' . substr($code, 0, 80));
        throw new RuntimeException('MCP moderation request failed.');
    }
    $decoded = json_decode($response, true);
    $result = is_array($decoded) ? ($decoded['results'][0] ?? null) : null;
    if (!is_array($result) || !is_array($result['categories'] ?? null)) {
        throw new RuntimeException('MCP moderation returned an invalid response.');
    }
    return $result;
}

/** Screen sanitized image bytes before an MCP upload or image result is returned. */
function mcp_content_safety_assert_image(string $bytes): void
{
    mcp_content_safety_assert_images([$bytes]);
}

/** The moderation API accepts one image per request; bound the whole preview check to 15s. */
function mcp_content_safety_assert_images(array $images): void
{
    if (!mcp_content_safety_active()) return;
    if (count($images) > 5) throw new RuntimeException('Too many images in one safety check.');
    $input = [];
    $pending = [];
    $total = 0;
    foreach ($images as $bytes) {
        if (!is_string($bytes)) throw new McpPlanError('INVALID_IMAGE', 'This image could not be checked.');
        $total += strlen($bytes);
        $info = @getimagesizefromstring($bytes);
        if ($total > 20_000_000 || !is_array($info)
            || !in_array($info['mime'] ?? '', ['image/png', 'image/jpeg', 'image/webp'], true)) {
            throw new McpPlanError('INVALID_IMAGE', 'This image could not be checked.');
        }
        $digest = hash('sha256', 'mcp-image-safety/v1:' . (getenv('OPENAI_MODERATION_MODEL') ?: 'omni-moderation-latest') . ':' . $bytes);
        if (isset($GLOBALS['mcp_content_safety_image_passes'][$digest]) || isset($pending[$digest])) continue;
        $pending[$digest] = $bytes;
        $input[] = ['type' => 'image_url', 'image_url' => ['url' => 'data:' . $info['mime'] . ';base64,' . base64_encode($bytes)]];
    }
    if ($input === []) return;
    try {
        $provider = $GLOBALS['mcp_content_safety_image_provider'] ?? null;
        $results = [];
        if (is_callable($provider)) {
            $results[] = $provider(array_values($pending));
        } else {
            $deadline = microtime(true) + 15;
            foreach ($input as $image) {
                $remaining = (int) floor(($deadline - microtime(true)) * 1000);
                if ($remaining < 1) throw new RuntimeException('Image moderation deadline exceeded.');
                $results[] = mcp_content_safety_request([$image], $remaining);
            }
        }
        // These categories support image inputs. Text-only categories cannot screen images.
        foreach ($results as $result) {
        foreach (['sexual', 'violence/graphic', 'self-harm/instructions'] as $category) {
            if (!is_array($result) || !is_bool($result['categories'][$category] ?? null)) {
                throw new RuntimeException('Image moderation response is incomplete.');
            }
            if ($result['categories'][$category]) {
                throw new McpPlanError('CONTENT_NOT_ALLOWED', 'This artwork is not available in this workflow.');
            }
        }
        }
        foreach (array_keys($pending) as $digest) $GLOBALS['mcp_content_safety_image_passes'][$digest] = true;
    } catch (McpPlanError $e) {
        throw $e;
    } catch (Throwable $e) {
        error_log('ai-coloring-book-mcp image gate: result=unavailable error=' . get_class($e));
        throw new McpPlanError('SAFETY_CHECK_UNAVAILABLE', 'The artwork check is temporarily unavailable. Please try again.');
    }
}

/**
 * Refuse mature sexual, graphic-violence, self-harm-instruction and illicit-instruction content.
 * Model labels are signals and can change; keep this narrow and regression-tested rather than
 * blocking every moderation `flagged` result (which would reject ordinary difficult subject matter).
 */
function mcp_content_safety_blocked_categories(array $result): array
{
    $categories = $result['categories'] ?? null;
    if (!is_array($categories)) throw new RuntimeException('MCP moderation categories are missing.');
    $blocked = ['sexual', 'sexual/minors', 'violence/graphic', 'self-harm/instructions', 'illicit',
        'illicit/violent', 'hate/threatening', 'harassment/threatening'];
    $hits = [];
    foreach ($blocked as $category) {
        if (!array_key_exists($category, $categories) || !is_bool($categories[$category])) {
            throw new RuntimeException('MCP moderation category response is incomplete.');
        }
        if ($categories[$category]) $hits[] = $category;
    }
    return $hits;
}

/** Fail closed on service trouble. Never include customer content in logs or exception messages. */
function mcp_content_safety_assert_suitable(array $value, string $stage): void
{
    if (!mcp_content_safety_active()) return;
    $chunks = mcp_content_safety_chunks($value);
    try {
        foreach ($chunks as $text) {
            $hits = mcp_content_safety_blocked_categories(mcp_content_safety_moderate($text));
            if ($hits !== []) {
                error_log('ai-coloring-book-mcp content gate: result=blocked stage=' . preg_replace('/[^a-z_]/', '', $stage)
                    . ' categories=' . implode(',', $hits));
                throw new McpPlanError('CONTENT_NOT_ALLOWED',
                    'This content is not available in this workflow. Please revise it and try again.');
            }
        }
    } catch (McpPlanError $exception) {
        throw $exception;
    } catch (Throwable $exception) {
        error_log('ai-coloring-book-mcp content gate: result=unavailable stage=' . preg_replace('/[^a-z_]/', '', $stage)
            . ' error=' . get_class($exception));
        throw new McpPlanError('SAFETY_CHECK_UNAVAILABLE',
            'The content check is temporarily unavailable. No book data was saved and nothing was charged; please try again.');
    }
}
