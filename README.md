# AI Coloring Book MCP

A [Model Context Protocol](https://modelcontextprotocol.io) server, in plain PHP, that exposes **coloring-book tools only**:
plan a book, quote it, start generation, watch progress with real artwork, swap in a custom cover, and export a
print-ready interior PDF and an Amazon KDP cover wrap. Point ChatGPT, Claude or any MCP client at it.

This package is the MCP layer. It does not draw anything itself. Generation (planning, page art, covers, PDFs) is done by the
**[AI Coloring Book Engine](https://github.com/WesBlackmore/ai-coloring-book-engine)**, which this package **requires**.

- Ten tools, three permission scopes, personal access tokens (PATs) out of the box.
- Optional OAuth 2.1 (the ChatGPT connector flow), off by default.
- No billing, no user database. Money is one optional host callback (the charge hook). Ownership is an opaque `account_id` string.
- Content safety (OpenAI moderation) on by default.
- KDP correctness kept: a 300 PPI cover-source check, and guidance text that forbids calling a below-300-PPI wrap KDP-ready.
- Vanilla PHP 8.2+, SQLite in WAL mode, no framework.

## Requirements

- PHP 8.2 or newer with `pdo_sqlite`, `gd`, `curl`, `mbstring` (and `openssl` for OAuth)
- [Composer](https://getcomposer.org/)
- The engine, installed next to this package (below)
- An OpenAI API key for real generation. Not needed for the offline example or the self-check.

## Install

The engine is **not** vendored or copied into this repo. It is a separate project that you clone beside the code (the
`engine/` directory is gitignored here).

```bash
git clone https://github.com/WesBlackmore/ai-coloring-book-mcp.git
cd ai-coloring-book-mcp
composer install            # mcp/sdk, nyholm/psr7 (+ league/oauth2-server and firebase/php-jwt for OAuth)
composer install-engine     # git clone of the engine into ./engine, then composer install inside it
```

`composer install-engine` is a convenience for two commands you can also run yourself:

```bash
git clone https://github.com/WesBlackmore/ai-coloring-book-engine.git engine
composer install -d engine
```

To keep the engine elsewhere, set `COLORING_ENGINE_PATH=/path/to/engine`. The engine needs its own `vendor/` (it uses
`dompdf`), which is why it is installed with Composer in its own directory. If the engine is missing, the package stops with a
message that says how to install it.

For a PAT-only install you can skip the OAuth libraries: `composer install --no-dev`.

## Try it with no key and no network

```bash
php tools/selfcheck.php          # 104 assertions, offline
php examples/offline-example.php # MCP handlers -> engine -> interior PDF, offline
```

Both swap the engine's AI providers for fakes through its seam (`$GLOBALS['coloring_worker_providers']`), so the pages are
placeholder rings, not real art. The example creates a book through the MCP create handler, quotes it (free by default), starts
it, runs the engine worker to completion, prepares and fetches the interior PDF, and prints its path.

## Configuration

Everything is an environment variable. Nothing is hardcoded and no keys ship with this repo.

| Variable | Default | What it does |
|---|---|---|
| `OPENAI_API_KEY` | none | Passed through to the engine for real generation, and used for moderation. With no key, generation records a failure and moderation is skipped with a logged warning. |
| `COLORING_ENGINE_PATH` | `./engine` | Where the engine is cloned. |
| `COLORING_DATA_DIR` | `<engine>/data` | Database, images, export artifacts, MCP sessions, rate-limit counters. Keep it outside the web root. |
| `COLORING_DATABASE_PATH` | `<data dir>/coloring.db` | The SQLite file. The engine and this package share it (engine tables plus `mcp_*` tables). |
| `OPENAI_IMAGE_MODEL`, `OPENAI_IMAGE_QUALITY`, `OPENAI_TEXT_MODEL`, `COLORING_PAGE_PARALLEL`, ... | engine defaults | Every model, quality, parallelism and retry setting the engine reads. See the engine README. |
| `MCP_PUBLIC_BASE_URL` | `http://127.0.0.1:8080` | Public origin of `public/index.php`. Used for download links and OAuth URLs. |
| `MCP_ALLOWED_HOSTS` | none | Extra comma-separated `Host` values the endpoint answers for (the host of `MCP_PUBLIC_BASE_URL`, `localhost` and `127.0.0.1` are always allowed). Any other host gets 403. Non-local hosts must be served over HTTPS (`HTTPS=on`). |
| `MCP_PAT_PEPPER` | none | Optional secret. When set, token secrets are stored as `HMAC-SHA256(pepper, token)`, so a copied database cannot be used to verify guesses. Changing it invalidates every issued token. |
| `MCP_PAT_MAX_DAYS` | `90` | Longest PAT lifetime that can be issued. |
| `MCP_RATE_LIMIT_PER_HOUR` | `240` | Requests per account per hour (429 beyond it). |
| `MCP_CONTENT_SAFETY` | on | Set `0` to switch the moderation gate off on purpose. |
| `OPENAI_MODERATION_MODEL` | `omni-moderation-latest` | Moderation model. |
| `MCP_COLORING_ENABLED` | on | Set `0` to hide the coloring tools (kill switch). |
| `MCP_HOOKS_FILE` | none | A PHP file `public/index.php` includes to register the charge hooks and the OAuth account resolver. |
| `MCP_OAUTH_ENABLED` | off | `1` loads the OAuth module (below). |
| `MCP_OAUTH_PRIVATE_KEY_PATH`, `MCP_OAUTH_KEY_ID`, `MCP_OAUTH_ENCRYPTION_KEY` or `MCP_OAUTH_ENCRYPTION_KEY_PATH`, `MCP_OAUTH_LOGIN_URL`, `MCP_OAUTH_ISSUER`, `MCP_OAUTH_RESOURCE` | none | OAuth settings, described below. |

### Content safety and a missing key

Plans are screened before they are saved and every returned image preview is screened before it leaves the server, using OpenAI
moderation. With a key set the gate **fails closed**: a moderation outage blocks the call with `SAFETY_CHECK_UNAVAILABLE`.
Moderation needs `OPENAI_API_KEY`, so with **no key the gate is skipped and one warning is written to the PHP error log**
(`moderation is SKIPPED`). A keyless run is never a hard failure. Real generation still needs the key anyway.

## Run the server

```bash
export COLORING_DATA_DIR=/var/lib/coloring-mcp
export OPENAI_API_KEY=...                        # your own key
php -S 127.0.0.1:8080 -t public public/index.php # development; use a real web server in production
php bin/worker --limit=20                        # run from cron every minute, see below
```

Routes served by `public/index.php`:

| Route | What |
|---|---|
| `POST /mcp` | The MCP endpoint (Streamable HTTP, short request/response exchanges). |
| `GET /download?artifact=art_...` | Bearer-token PDF download. Needs a token with READ and EXPORT. |
| `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp`, `/oauth/jwks.json`, `/oauth/authorize`, `/oauth/token` | Only when `MCP_OAUTH_ENABLED=1`. |

Tool calls never advance generation. **`bin/worker` does**: it runs one pass of the engine's queue (plan already saved, pages,
cover, cover outline, finish) and then one pass of the PDF export queue. Schedule it, for example `* * * * * php /path/bin/worker`.

## Personal access tokens (the default auth)

```bash
php bin/token issue acct-123 "My laptop" --days=30 --scopes=read,write,export
php bin/token list acct-123
php bin/token revoke acct-123 <token_id>
```

The raw token (`mcp_pat_<id>_<secret>`) is printed once and only a hash is stored. Send it as `Authorization: Bearer <token>`.
`account_id` is any opaque string you choose (1 to 128 characters of `A-Za-z0-9_.@:+-`): a user id, an email hash, a tenant slug.
The package never interprets it. From code: `mcp_pat_issue($accountId, $label, $days, null, $scopes)`.

Scopes are cumulative per tool. READ is mandatory on every token.

| Scope | Constant | Grants |
|---|---|---|
| `books:read` | `MCP_PAT_READ_SCOPE` | List and read books. |
| `books:write` | `MCP_PAT_WRITE_SCOPE` | Create, quote, start, apply a custom cover. |
| `books:export` | `MCP_PAT_EXPORT_SCOPE` | Prepare and read PDF exports, download. |

## Tools

| Tool | Scopes | What it does |
|---|---|---|
| `list_my_coloring_books` | read | The account's books with progress. |
| `get_coloring_book` | read | Progress plus real artwork (cover, outline, up to four drawings per call, paginate with `image_offset`). Renders the bundled viewer widget. Never advances generation. |
| `create_coloring_book` | read, write | Save a complete plan with one scene per drawing as a draft. No images, no charge. Idempotent on a UUIDv4 `create_command_id`. |
| `quote_coloring_book` | read, write | Price the saved plan through the `quote_cost` hook (free by default). Valid 15 minutes. |
| `start_coloring_book` | read, write | Run the `charge` hook, then queue generation. A denied charge generates nothing. |
| `apply_custom_coloring_cover` | read, write | Replace the cover with a user-supplied image (ChatGPT file param). Reports effective PPI. |
| `prepare_coloring_pdf` | read, export | Queue the complete interior PDF (cover, cover outline page, overview sheets, drawings). |
| `get_coloring_pdf` | read, export | State of that export. A download link appears only when it is ready and current. |
| `prepare_coloring_cover_wrap` | read, export | Queue the separate Amazon KDP paperback cover wrap (back, calculated spine, front). |
| `get_coloring_cover_wrap` | read, export | State of the wrap export, with source pixels and effective PPI. |

Exports are immutable snapshots keyed by content, cover and renderer version. If the book or cover changes, an old artifact
reports `state: stale`, `is_current: false` and no link; prepare again without an `artifact_id`.

### The KDP 300 PPI rule

Amazon KDP's published minimum for cover images is 300 DPI. For every custom cover and every cover wrap this server measures the
source image **after the exact crop used by the front panel** (8.625 x 11.25 in) and returns `cover_source_width_px`,
`cover_source_height_px`, `cover_source_ppi_x`, `cover_source_ppi_y`, `cover_source_meets_300ppi` and a plain-language
`cover_source_resolution_note`. Retaining 300 PPI over the full panel needs about 2588 x 3375 effective pixels.

- Below 300 PPI the note says the cover does not meet KDP's minimum, may be flagged or rejected, and must not be submitted as KDP-ready. The user may still print it personally, but it may look soft or pixelated, and PDF resampling does not restore detail.
- If the cover cannot be measured at all, the result is `null` and the note still says not to treat the wrap as KDP-ready.
- The server instructions given to the model contain the rule verbatim: **never call a below-300-PPI wrap KDP-ready**.

Dimensions come from the engine's print-cover calculations. Do not claim KDP acceptance; check the final PDF with KDP's Cover
Calculator and Previewer.

## Money: the charge hook

There is no wallet, no credits, no plans. If you want to charge for generation, register two optional callbacks. With none
registered every quote costs 0 and every start is approved, so a standalone install generates with no billing wired.

```php
// hooks.php, loaded by public/index.php when MCP_HOOKS_FILE=/path/to/hooks.php
mcp_register_hooks([
    // Called by quote_coloring_book and again by start_coloring_book (a price that moved since the quote is refused).
    'quote_cost' => function (array $ctx): array {
        // $ctx: account_id, book_token, title, drawings_total, plan_revision
        $cost = $ctx['drawings_total'] * 2;
        return ['cost' => $cost, 'unit' => 'credits', 'message' => "$cost credits", 'can_start' => my_balance($ctx['account_id']) >= $cost];
    },
    // Called once, right before the engine runs. Return true/false or an array.
    'charge' => function (array $ctx): array {
        // $ctx adds: quote_id, cost, unit, idempotency_key (== quote_id)
        $ok = my_reserve($ctx['account_id'], $ctx['cost'], $ctx['idempotency_key']);
        return ['approved' => $ok, 'reason' => $ok ? '' : 'Insufficient balance', 'reference' => 'txn-123'];
    },
]);
```

- `quote_cost` may return an int, or `['cost' => int, 'unit' => string, 'message' => string, 'can_start' => bool]`. It must be fast and free of side effects.
- `charge` may return a bool or `['approved' => bool, 'reason' => string, 'reference' => string]`. **A denial stops the start: the engine never runs.**
- Every decision, approved or denied, is written to the `mcp_charge_ledger` table.
- Make `charge` idempotent on `idempotency_key`. The quote is consumed only when the start commits, so a retried start after a lost response will not charge twice, but a crash between your side effect and the commit can call you again with the same key.
- This package does not refund. If the engine later fails, retry or refund in your own code (the worker status shows `stalled`).

## OAuth 2.1 (optional)

PAT auth is complete on its own. For the ChatGPT connector flow (authorization code with PKCE S256, rotating refresh tokens,
RS256 JWT access tokens, client ID metadata document for `https://chatgpt.com/oauth/client.json`), set `MCP_OAUTH_ENABLED=1`.
PATs keep working alongside it.

1. Generate keys (outside the web root, owner-only):
   ```bash
   openssl genrsa -out oauth-private.pem 2048 && chmod 600 oauth-private.pem
   php -r 'require "vendor/autoload.php"; echo Defuse\Crypto\Key::createNewRandomKey()->saveToAsciiSafeString(), "\n";' > oauth-encryption.key && chmod 600 oauth-encryption.key
   ```
2. Set the variables:
   ```bash
   MCP_OAUTH_ENABLED=1
   MCP_PUBLIC_BASE_URL=https://mcp.example.com      # HTTPS, no path. Issuer must equal it; resource is <base>/mcp
   MCP_OAUTH_PRIVATE_KEY_PATH=/secure/oauth-private.pem
   MCP_OAUTH_KEY_ID=key-1
   MCP_OAUTH_ENCRYPTION_KEY_PATH=/secure/oauth-encryption.key   # or MCP_OAUTH_ENCRYPTION_KEY
   MCP_OAUTH_LOGIN_URL=https://app.example.com/login            # where an anonymous browser is sent
   ```
3. Tell the package who is signed in. The package has no login of its own; your hooks file supplies the browser's account:
   ```php
   $GLOBALS['mcp_oauth_account_resolver'] = fn(): ?array =>
       isset($_SESSION['user']) ? ['id' => (string) $_SESSION['user']['id'], 'label' => $_SESSION['user']['email']] : null;
   ```
   After login, send the browser back to `/oauth/authorize` (the parked request is kept in the PHP session).
4. Serve `/mcp`, `/oauth/authorize`, `/oauth/token`, `/oauth/jwks.json` and the two `/.well-known/...` paths from `public/index.php` over HTTPS.

Grants, codes, access tokens and refresh tokens live in the `mcp_oauth_*` tables, keyed by `account_id`. Revoke a grant with
`mcp_oauth_store_revoke_grant($accountId, $grantId)`. Replaying a used refresh token revokes the whole token family.

## Layout

```
src/autoload.php             one entry point: Composer, the engine, then the files below
src/db.php                   shares the engine's SQLite connection (WAL) and adds the mcp_* tables
src/mcp_server.php           the MCP server (coloring tools only), scopes, HTTP serving, rate limit
src/mcp_coloring.php         create, list, status, custom cover, 300 PPI check
src/mcp_coloring_exports.php PDF and cover-wrap exports: snapshot, staleness, claim, render, publish, fail
src/mcp_quotes.php           quote + the quote_cost hook, hook registration
src/mcp_admission.php        start + the charge hook and ledger
src/mcp_auth.php             PATs and scopes
src/mcp_content_safety.php   moderation gate
src/mcp_custom_covers.php    safe fetch and re-encode of a user cover
src/mcp_tool_schemas.php     tool input and output schemas
src/mcp_common.php           errors, validation helpers
src/oauth/                   optional OAuth 2.1 (loaded only when MCP_OAUTH_ENABLED=1)
resources/coloring-viewer.html  the viewer widget resource
public/index.php             front controller
bin/token, bin/worker        token management, background worker
examples/offline-example.php runnable offline end-to-end example
tools/selfcheck.php          the test suite
```

## Notes

- `composer.json` pins `mcp/sdk` at 0.8.1 and ignores advisory PKSA-s52d-n7sx-trsg. It concerns the SDK's own OAuth middleware endpoints, which this package does not mount; OAuth here is served by `src/oauth/http.php` with explicit request-size limits. Review the advisory and your own threat model before enabling OAuth in production.
- Real image generation costs money and is the engine's behavior; this package adds no spend of its own. The engine has hourly and daily call caps (`AI_RATE_ACTOR_HOUR`, `AI_RATE_GLOBAL_DAY`).
- No secrets, keys or account data are committed. Everything is read from the environment.

## License

MIT, see [LICENSE](LICENSE).
