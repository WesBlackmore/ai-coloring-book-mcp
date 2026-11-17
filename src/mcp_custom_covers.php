<?php

declare(strict_types=1);

const MCP_CUSTOM_COVER_MAX_BYTES = 20_000_000;
const MCP_CUSTOM_COVER_MAX_PIXELS = 12_000_000;
// The coloring-book front panel is 8.625 x 11.25 in (0.7667:1). ChatGPT image output rounds to nearby
// ratios such as 1098 x 1433 (0.7662:1); allow a small margin, then crop proportionally in the print renderer.
const MCP_CUSTOM_COLORING_COVER_MAX_RATIO = 0.78;

function mcp_chatgpt_image_host_is_trusted(string $host): bool
{
    return $host === 'oaiusercontent.com' || str_ends_with($host, '.oaiusercontent.com')
        || $host === 'chatgpt.com' || str_ends_with($host, '.chatgpt.com')
        // ChatGPT fileParams hands generated images off through a region-specific Azure Blob account family.
        || preg_match('/^oaisdmnt[a-z0-9-]+\.blob\.core\.windows\.net$/D', $host) === 1;
}

/**
 * Fetch a short-lived ChatGPT file URL without allowing arbitrary server-side requests.
 * The accepted origins are deliberately narrow; redirects are disabled and DNS is pinned
 * to a publicly routable address before TLS verification.
 */
function mcp_chatgpt_image_bytes(string $url): string
{
    $override = $GLOBALS['mcp_image_fetcher'] ?? null;
    if (is_callable($override)) return (string) $override($url);
    $parts = parse_url($url);
    if (!is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
        || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
        || (isset($parts['port']) && (int) $parts['port'] !== 443)) {
        throw new McpPlanError('INVALID_IMAGE', 'ChatGPT could not provide a secure image download.');
    }
    $host = strtolower(rtrim((string) ($parts['host'] ?? ''), '.'));
    if (!mcp_chatgpt_image_host_is_trusted($host) || $host === ''
        || filter_var($host, FILTER_VALIDATE_IP)) {
        throw new McpPlanError('INVALID_IMAGE', 'The ChatGPT file download origin is not supported.');
    }
    if (!function_exists('curl_init')) {
        throw new RuntimeException('Secure image downloading is unavailable on this host.');
    }

    $records = dns_get_record($host, DNS_A);
    $address = null;
    foreach (is_array($records) ? $records : [] as $record) {
        $candidate = (string) ($record['ip'] ?? '');
        if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4
            | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $address = $candidate;
            break;
        }
    }
    if ($address === null) {
        throw new McpPlanError('INVALID_IMAGE', 'The ChatGPT image host could not be verified.');
    }

    $body = '';
    $handle = curl_init($url);
    if ($handle === false) throw new RuntimeException('Secure image downloading is unavailable.');
    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_RESOLVE => [$host . ':443:' . $address],
        CURLOPT_USERAGENT => 'AI-Coloring-Book-MCP/1.0',
        CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body): int {
            if (strlen($body) + strlen($chunk) > MCP_CUSTOM_COVER_MAX_BYTES) return 0;
            $body .= $chunk;
            return strlen($chunk);
        },
    ]);
    $ok = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);
    if ($ok !== true || $status !== 200 || $body === '') {
        throw new McpPlanError('INVALID_IMAGE', 'The ChatGPT image could not be downloaded. Try the image again.');
    }
    return $body;
}

/** Decode supported raster formats and re-encode to a metadata-free PNG cover asset. */
function mcp_custom_cover_png(string $bytes, float $maxPortraitRatio = MCP_CUSTOM_COLORING_COVER_MAX_RATIO): string
{
    if (!is_finite($maxPortraitRatio) || $maxPortraitRatio < 0.55 || $maxPortraitRatio > 0.9) {
        throw new InvalidArgumentException('Invalid custom cover portrait ratio limit.');
    }
    if ($bytes === '' || strlen($bytes) > MCP_CUSTOM_COVER_MAX_BYTES
        || !function_exists('imagecreatefromstring') || !function_exists('imagepng')) {
        throw new McpPlanError('INVALID_IMAGE', 'The image is unavailable or too large to use as a cover.');
    }
    $info = @getimagesizefromstring($bytes);
    $mime = is_array($info) ? (string) ($info['mime'] ?? '') : '';
    $width = is_array($info) ? (int) ($info[0] ?? 0) : 0;
    $height = is_array($info) ? (int) ($info[1] ?? 0) : 0;
    if (!in_array($mime, ['image/png', 'image/jpeg', 'image/webp'], true)
        || $width < 500 || $height < 750 || $width * $height > MCP_CUSTOM_COVER_MAX_PIXELS
        || $width / $height < 0.55 || $width / $height > $maxPortraitRatio) {
        throw new McpPlanError('INVALID_IMAGE',
            'Use a PNG, JPEG, or WebP portrait image close to the coloring-book front-panel ratio (about 0.767:1), '
            . 'at least 500 x 750 pixels.');
    }
    $image = @imagecreatefromstring($bytes);
    if ($image === false) throw new McpPlanError('INVALID_IMAGE', 'The image file could not be decoded.');
    imagesavealpha($image, true);
    ob_start();
    $saved = imagepng($image, null, 6);
    $png = ob_get_clean();
    if ($saved !== true || !is_string($png) || $png === '' || strlen($png) > MCP_CUSTOM_COVER_MAX_BYTES) {
        throw new McpPlanError('INVALID_IMAGE', 'The image could not be safely prepared as a book cover.');
    }
    return $png;
}
