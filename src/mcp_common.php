<?php

declare(strict_types=1);

/** A domain error with a stable machine code, returned to the MCP client as a structured tool error. */
final class McpPlanError extends RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/** Account ids are opaque host-chosen strings. Keep them boring so they are safe in keys and file names. */
function mcp_account_id_valid(string $accountId): bool
{
    return preg_match('/^[A-Za-z0-9_.@:+-]{1,128}$/D', $accountId) === 1;
}

/** Reject unknown and missing properties rather than silently dropping author choices. */
function mcp_plan_require_keys(array $value, array $keys, string $field): void
{
    if (array_is_list($value)) throw new McpPlanError('VALIDATION_ERROR', "$field must be an object.");
    $actual = array_keys($value);
    sort($actual);
    sort($keys);
    if ($actual !== $keys) throw new McpPlanError('VALIDATION_ERROR', "$field has missing or unsupported fields.");
}

function mcp_plan_text(mixed $value, int $limit, string $field, bool $required = true): string
{
    if (!is_string($value) || !mb_check_encoding($value, 'UTF-8') || mb_strlen($value) > $limit
        || str_contains($value, "\0") || ($required && trim($value) === '')) {
        throw new McpPlanError('VALIDATION_ERROR', "$field must be valid text of up to $limit characters.");
    }
    return $value;
}

/** Canonicalize object-key order for a retry fingerprint; array order remains meaningful. */
function mcp_plan_hash_value(mixed $value): mixed
{
    if (!is_array($value)) return $value;
    if (array_is_list($value)) return array_map('mcp_plan_hash_value', $value);
    ksort($value, SORT_STRING);
    foreach ($value as &$child) $child = mcp_plan_hash_value($child);
    unset($child);
    return $value;
}

function mcp_plan_command_id(string $commandId): void
{
    if (preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/iD', $commandId) !== 1) {
        throw new McpPlanError('VALIDATION_ERROR', 'create_command_id must be a UUIDv4.');
    }
}

/** Where download links point. Set MCP_PUBLIC_BASE_URL to the public origin of public/index.php. */
function mcp_public_base_url(): string
{
    $configured = rtrim(trim((string) getenv('MCP_PUBLIC_BASE_URL')), '/');
    return $configured !== '' ? $configured : 'http://127.0.0.1:8080';
}
