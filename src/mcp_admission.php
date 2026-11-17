<?php

declare(strict_types=1);

/**
 * Run the host's charge hook for one quote. Every decision is written to mcp_charge_ledger, approved or denied.
 *
 * @return array{approved:bool,reason:string,reference:?string}
 */
function mcp_hook_charge(array $context, PDO $pdo): array
{
    $hook = $GLOBALS['mcp_hooks']['charge'] ?? null;
    $result = is_callable($hook) ? $hook($context) : true;
    $approved = is_array($result) ? (bool) ($result['approved'] ?? false) : $result === true;
    $reason = is_array($result) ? (string) ($result['reason'] ?? '') : '';
    $reference = is_array($result) && isset($result['reference']) ? (string) $result['reference'] : null;
    $pdo->prepare('INSERT INTO mcp_charge_ledger (account_id, book_token, quote_id, amount, decision, reason, reference)
        VALUES (?, ?, ?, ?, ?, ?, ?)')->execute([$context['account_id'], $context['book_token'], $context['quote_id'],
            $context['cost'], $approved ? 'approved' : 'denied', $reason !== '' ? mb_substr($reason, 0, 300) : null, $reference]);
    return ['approved' => $approved, 'reason' => $reason, 'reference' => $reference];
}

function mcp_coloring_start(string $accountId, string $bookToken, string $quoteId, int $revision): array
{
    if (preg_match('/^cq_[a-f0-9]{24}$/D', $quoteId) !== 1) {
        throw new McpPlanError('VALIDATION_ERROR', 'Use the quote ID returned by quote_coloring_book.');
    }
    $pdo = mcp_db();
    // The engine's coloring_worker_start joins a caller-owned transaction, so the quote and the queue write commit together.
    $pdo->beginTransaction();
    $denied = null;
    try {
        $project = mcp_coloring_owned($accountId, $bookToken, $pdo);
        if ($project === null) throw new McpPlanError('NOT_AVAILABLE', 'That coloring book is not available to this account.');
        $quoteQuery = $pdo->prepare('SELECT * FROM mcp_coloring_quotes WHERE account_id = ? AND book_token = ? AND quote_id = ?');
        $quoteQuery->execute([$accountId, $bookToken, $quoteId]);
        $quote = $quoteQuery->fetch(PDO::FETCH_ASSOC);
        if (!is_array($quote)) throw new McpPlanError('NOT_AVAILABLE', 'That quote is not available for this coloring book.');
        if ($revision !== (int) $quote['plan_revision']) {
            throw new McpPlanError('REVISION_CONFLICT', 'The requested plan revision does not match this quote.');
        }
        // Resolve a committed start before expiry or price validation, so a retry after a lost response is harmless.
        if ($quote['consumed_at'] !== null) {
            if (!in_array((string) $project['status'], ['queued', 'generating', 'ready'], true)) {
                throw new McpPlanError('NOT_AVAILABLE', 'That quote has already been used.');
            }
            $pdo->commit();
            return mcp_coloring_start_result($bookToken, $project, (int) $quote['cost']);
        }
        $currentHash = mcp_coloring_project_hash($project);
        $price = mcp_hook_quote_cost(mcp_coloring_cost_context($accountId, $project));
        if ($revision !== (int) $project['current_revision']
            || !hash_equals((string) $quote['plan_hash'], $currentHash)
            || !hash_equals((string) $project['current_plan_hash'], $currentHash)
            || $price['cost'] !== (int) $quote['cost']) {
            throw new McpPlanError('REVISION_CONFLICT', 'The plan or price changed. Review the current plan and request a fresh quote.');
        }
        if ((string) $quote['expires_at'] <= gmdate('Y-m-d H:i:s')) {
            throw new McpPlanError('QUOTE_EXPIRED', 'The quote expired. Request a fresh quote before starting.');
        }
        if (!$price['can_start']) {
            throw new McpPlanError('CHARGE_DENIED', $price['message'] !== '' ? $price['message'] : 'This book cannot be started.');
        }
        $charge = mcp_hook_charge(mcp_coloring_cost_context($accountId, $project) + [
            'quote_id' => $quoteId, 'cost' => $price['cost'], 'unit' => $price['unit'], 'idempotency_key' => $quoteId], $pdo);
        if (!$charge['approved']) {
            // Keep the ledger row, then leave without running the engine.
            $pdo->commit();
            $denied = $charge['reason'] !== '' ? $charge['reason'] : 'The charge was not approved.';
        } else {
            $started = coloring_worker_start((int) $project['project_id']);
            $pdo->prepare("UPDATE mcp_coloring_quotes SET consumed_at = COALESCE(consumed_at, datetime('now')) WHERE quote_id = ? AND account_id = ?")
                ->execute([$quoteId, $accountId]);
            $pdo->commit();
            return mcp_coloring_start_result($bookToken, $started, $price['cost']);
        }
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $exception;
    }
    throw new McpPlanError('CHARGE_DENIED', $denied);
}

function mcp_coloring_start_result(string $bookToken, array $started, int $charged): array
{
    return ['book_id' => $bookToken, 'title' => (string) $started['title'],
        'state' => (string) $started['status'], 'charged' => $charged,
        'drawings_total' => coloring_project_pages($started),
        'next_action' => 'Use get_coloring_book to check progress and view completed drawings. Generation runs in the worker; status reads never advance it.'];
}
