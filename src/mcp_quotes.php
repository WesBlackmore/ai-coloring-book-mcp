<?php

declare(strict_types=1);

const MCP_QUOTE_LIFETIME_SECONDS = 900;

/**
 * Register the host's money hooks. Both are optional; with none registered every book is free and every start
 * is approved, so a standalone install generates with no billing wired.
 *
 *   quote_cost: callable(array $context): int|array
 *       Price one start. Return an int, or ['cost' => int, 'unit' => 'credits', 'message' => string, 'can_start' => bool].
 *   charge: callable(array $context): bool|array
 *       Called once, with an idempotency_key (the quote id), right before the engine runs. Return true/false, or
 *       ['approved' => bool, 'reason' => string, 'reference' => string]. A denial stops the start; nothing is generated.
 *
 * $context carries account_id, book_token, title, drawings_total, plan_revision and, for charge, quote_id, cost, unit.
 *
 * @param array{quote_cost?:callable,charge?:callable} $hooks
 */
function mcp_register_hooks(array $hooks): void
{
    foreach (['quote_cost', 'charge'] as $name) {
        if (array_key_exists($name, $hooks)) {
            if ($hooks[$name] !== null && !is_callable($hooks[$name])) {
                throw new InvalidArgumentException("The $name hook must be callable.");
            }
            $GLOBALS['mcp_hooks'][$name] = $hooks[$name];
        }
    }
}

/** @return array{cost:int,unit:string,message:string,can_start:bool} */
function mcp_hook_quote_cost(array $context): array
{
    $hook = $GLOBALS['mcp_hooks']['quote_cost'] ?? null;
    $result = is_callable($hook) ? $hook($context) : 0;
    $detail = is_array($result) ? $result : ['cost' => $result];
    $cost = $detail['cost'] ?? 0;
    if (filter_var($cost, FILTER_VALIDATE_INT) === false || (int) $cost < 0) {
        throw new RuntimeException('The quote_cost hook must return a non-negative integer cost.');
    }
    $cost = (int) $cost;
    return ['cost' => $cost, 'unit' => (string) ($detail['unit'] ?? ''),
        'message' => (string) ($detail['message'] ?? ($cost === 0 ? 'Free: no charge is configured.' : '')),
        'can_start' => (bool) ($detail['can_start'] ?? true)];
}

function mcp_coloring_quote(string $accountId, string $bookToken, int $revision, ?PDO $pdo = null): array
{
    $pdo ??= mcp_db();
    $project = mcp_coloring_owned($accountId, $bookToken, $pdo);
    if ($project === null) throw new McpPlanError('NOT_AVAILABLE', 'That coloring book is not available to this account.');
    if ($revision !== (int) $project['current_revision']) {
        throw new McpPlanError('REVISION_CONFLICT', 'Refresh the coloring-book plan before requesting a quote.');
    }
    if (!in_array((string) $project['status'], ['draft', 'planned'], true)) {
        throw new McpPlanError('NOT_AVAILABLE', 'This coloring book has already started or is no longer editable.');
    }
    $planHash = mcp_coloring_project_hash($project);
    if (!hash_equals((string) $project['current_plan_hash'], $planHash)) {
        throw new RuntimeException('Coloring plan hash is inconsistent.');
    }
    $price = mcp_hook_quote_cost(mcp_coloring_cost_context($accountId, $project));
    $quoteId = 'cq_' . bin2hex(random_bytes(12));
    $expires = gmdate('Y-m-d H:i:s', time() + MCP_QUOTE_LIFETIME_SECONDS);
    $pdo->prepare('INSERT INTO mcp_coloring_quotes
        (quote_id, account_id, book_token, plan_revision, plan_hash, cost, unit, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)')->execute([$quoteId, $accountId, $bookToken, $revision, $planHash,
            $price['cost'], $price['unit'], $expires]);
    return ['quote_id' => $quoteId, 'book_id' => $bookToken, 'plan_revision' => $revision,
        'cost' => $price['cost'], 'unit' => $price['unit'], 'can_start' => $price['can_start'],
        'message' => $price['message'], 'expires_at' => $expires];
}
