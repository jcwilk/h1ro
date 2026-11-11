# h1ro (Rust)

Read-only command-line client for the [HackerOne Hacker API](https://api.hackerone.com/getting-started-hacker-api/), designed for **agentic use**: progressive discovery, token-friendly compact output, unambiguous endpoint mapping. Rebuilt in Rust on 2026-11-10 after the box reboot; subcommand layer added the same day. The first Python version is kept as `h1ro.py.bak`.

Writes to HackerOne are impossible by construction: GET only, `https://api.hackerone.com/v1/hackers/*` only (see Safety invariants).

## Two invocation modes (backward-compat rule)

1. **Raw-path mode (unchanged, used by existing finder agents and the weekday routine).** If the first non-flag argument starts with `/`, the whole invocation is handled exactly as before subcommands existed:
   `h1ro [--dry-run] /v1/hackers/... [key=value ...]` - raw pretty JSON on stdout, `HTTP <code>: <body>` on stderr + exit 1 for 4xx/5xx, `refused: ...` + exit 1 for local refusals. Only `--dry-run` and `-h/--help` are flags here; anything else dash-leading is refused.
2. **Subcommand mode.** Otherwise the first token is a command (`programs`, `reports`, `payments`, `hacktivity`, `intents`, `raw`, `help`). Subcommands are only *builders* of an allowed `/v1/hackers` GET path + params; the result goes through the exact same `validate_path` / `validate_params` / `build_request` / `perform` as raw-path mode. The validator (not the builder) enforces the lock, and tests prove it refuses hostile handles/ids by itself.

## Command tree

```
h1ro                                 overview (also: help, --help, -h)
h1ro help [<cmd> [<sub>]]            overview or detailed help
h1ro programs                        lists subcommands
  programs list [--bounty-only] [list flags]        GET /v1/hackers/programs
  programs get <handle> [--max-chars N]             GET /v1/hackers/programs/<handle>
  programs scopes <handle> [list flags]             GET /v1/hackers/programs/<handle>/structured_scopes
  programs weaknesses <handle> [list flags]         GET /v1/hackers/programs/<handle>/weaknesses
  programs exclusions <handle> [list flags]         GET /v1/hackers/programs/<handle>/scope_exclusions
h1ro reports
  reports list [list flags]                         GET /v1/hackers/me/reports
  reports get <id> [--max-chars N]                  GET /v1/hackers/reports/<id>        (id: digits only)
h1ro payments
  payments balance                                  GET /v1/hackers/payments/balance
  payments earnings [list flags]                    GET /v1/hackers/payments/earnings
  payments payouts [list flags]                     GET /v1/hackers/payments/payouts
h1ro intents
  intents list [--fields a,b] [--max-chars N]       GET /v1/hackers/report_intents
  intents get <id> [--max-chars N]                  GET /v1/hackers/report_intents/<id> (id: digits only)
  intents attachments <id> [--fields a,b]           GET /v1/hackers/report_intents/<id>/attachments
h1ro hacktivity [--query LUCENE] [--sort FIELD] [list flags]
                                                    GET /v1/hackers/hacktivity
h1ro raw </v1/hackers/...> [key=value ...]          any allowed GET; pretty JSON; twin of raw-path mode
```

`h1ro <cmd> [<sub>] --help` prints usage, the **exact GET endpoint**, columns, flags, notes and an example. All paths above were verified as real read-only GETs against the live API (read calls only) or the Hacker API docs; anything else is left to `raw`.

Global flags (every command): `--json` (full response, pretty JSON, no truncation), `--dry-run` (print the exact GET it WOULD make, no network call, token hidden), `--help/-h`.
List flags: `--limit N` (1-100, = `page[size]=N`), `--page N` (>=1, = `page[number]=N`), `--fields a,b,c` (choose compact columns: `id` or any attribute name; unknown names are an error that lists the available ones), `--max-chars N` (truncate each cell, default 80 for lists, 200 for single objects; `0` = never truncate).
Read filters (still GET, still one request): `hacktivity --query` (Lucene `queryString`, one percent-encoded parameter) and `--sort` (the documented sort fields only, optional leading `-`). `programs scopes --since-id` (`filter[id__gt]`, required past 10,000 scopes), `--created-after`, `--updated-after` (ISO-8601 `filter[created_at__gt]` / `filter[updated_at__gt]`). `intents` sends no query string: the catalog documents none for those GETs.
`programs list` only: `--bounty-only` - **client-side** filter (`offers_bounties=true`) of the fetched page; the API returns all programs, so page through with `--page`. Ignored with `--json` (a footer line says so).

Flags may appear anywhere; `--limit=2` and `--limit 2` both work; a flag not valid for the chosen command is an `error:`.

## Output contract

- **stdout is data only.** **stderr** carries the footer and errors. Errors are prefixed `error:` (usage, HTTP, missing token, unknown field) or `refused:` (local safety refusal: path/param validator, redirects, non-JSON). Both exit 1. Help/overview exit 0.
- **List commands, compact mode:** line 1 is a tab-separated header naming the columns; then one record per line, tab-separated, stable column order. `null` = JSON null; booleans/numbers verbatim; tab/newline/CR inside values are escaped as `\t`, `\n`, `\r`; nested values are compact JSON. Truncated cells end with `…[+N chars]` (N = chars removed).
- **Columns (default):**
  - `programs list`: `handle, name, offers_bounties, state, submission_state`
  - `programs scopes`: `asset_type, asset_identifier, eligible_for_bounty, eligible_for_submission, max_severity`
  - `programs weaknesses`: `id, name, external_id`
  - `reports list`: `id, state, created_at, bounty_awarded_at, title, program` (`program` is the included program handle)
  - `intents list`: `id, state, title`
  - `intents attachments`: `id, file_name, content_type, file_size, created_at, expiring_url`
  - `hacktivity`: `id, submitted_at, disclosed, title, severity_rating, total_awarded_amount, substate, program`
  - `programs exclusions`: `id, category, details, created_at, updated_at`
  - `payments earnings`: `id, type, amount, created_at, program`
  - `payments payouts`: `amount, paid_out_at, status, payout_provider, reference` (flat records, no id)
- **Single objects** (`programs get`, `reports get`, `intents get`, `payments balance`): `key<TAB>value` lines - `id`, `type`, then every attribute in API order (long values truncated with the marker). `reports get` then prints the activities already embedded in that response (`created_at`, `type`, `actor`, `message`) and an attachments table (`id`, `file_name`, `content_type`, `file_size`, `expiring_url`) when any are present, including attachments nested on activities. Other relationships are named in the stderr footer, and `--json` has everything. `expiring_url` is printed and never requested. `/v1/hackers/me` is not a command: it is not in the Hacker API catalog and returns 401 for a Hacker API token. The path stays reachable with `h1ro raw /v1/hackers/me`. Liveness check: `programs list --limit 1`.
- **Footer (stderr) for lists**, e.g.
  `# programs scopes: 3 rows; page 1 of 33 (size 3); next: h1ro programs scopes dyson --limit 3 --page 2`
  Page/size/last come from the API's `links` (self/next/last) or the flags you passed. If the size is not reported it says `size: API default, not reported` instead of guessing; if the API sends no `last` link there is no "of N"; with no `next` link it says `end of results`. It also reports truncated-cell counts (`N cell(s) truncated at M chars; full: --json, or --max-chars 0`) and `--bounty-only` counts (`K of N rows kept ...`). The `next:` command preserves `--bounty-only`, `--fields`, `--max-chars`, `--json`. `raw` footers give `next: h1ro raw <path> 'page[size]=..' 'page[number]=..'`.
- `--json` / `raw`: full pretty JSON in API key order on stdout (the list footer still goes to stderr).
- `--dry-run` output (stdout): `DRY RUN: no network call made.` / `Would GET <url>` / `Auth: HTTP Basic (username=..., token from H1_API_TOKEN: present|NOT SET)`. Hostile input is still refused in dry-run.

## Usage examples

```bash
export H1_API_TOKEN=...          # env only; never a CLI arg
h1ro programs list --bounty-only --limit 100
h1ro programs scopes dyson --limit 100 --fields asset_type,asset_identifier
h1ro programs get dyson --max-chars 0
h1ro reports list --limit 25
h1ro hacktivity --query 'severity_rating:critical AND disclosed:true' --sort -disclosed_at
h1ro programs scopes dyson --since-id 9012 --limit 100
h1ro intents list
h1ro intents get 23
h1ro raw /v1/hackers/programs/dyson/weaknesses 'page[size]=5'
h1ro /v1/hackers/programs 'page[size]=1'           # raw-path mode, unchanged
h1ro programs list --dry-run --limit 2
```

## HTTP approach (and why)

`ureq` 2.x (blocking, rustls TLS, default features off so no gzip/json/cookies/proxy-from-env), pure Rust, resolved with the rust-version-aware resolver for rustc 1.85. All network code is in `src/http.rs`, which calls `agent.get(url)` and nothing else; a unit test scans that file and fails if any other verb call or body-sending call appears, or if a proxy is configured. The agent is `https_only(true)` with `redirects(0)`. Everything that decides whether a request may exist is pure code in `src/lib.rs`. The network layer only accepts a `ValidatedRequest` (private field, only constructible by `build_request`, which re-validates the path and every parameter), and the `Transport` trait has exactly one method, `get`. There is no code path that carries a method or a body.

## Safety invariants (each has unit tests, see `src/tests.rs`)

1. **GET only.** Hardcoded; no flag/arg/env var selects a verb; no body is ever sent. Only `--dry-run`, `-h`, `--help` are flags; any other dash-leading argument is refused (`-X`, `--data`, `--url`, ...).
2. **Host and prefix lock.** Only `https://api.hackerone.com`, only paths exactly `/v1/hackers` or `/v1/hackers/<segments>` where segments are non-empty ASCII `[A-Za-z0-9_.~-]`. `/v1/programs/...` and friends are refused locally. The host is a constant. `build_request` and `http.rs` both require the URL to be that host plus `/v1/hackers` with the next byte `/`, `?`, or the end, so `api.hackerone.com.evil` does not match. `https_only(true)` refuses an `http://` URL inside the HTTP client as well.
3. **Bare paths only.** Refused: scheme/host (`://`, `//host`), `?`, `#`, `@`, backslash, `%` (no percent-encoding at all), control characters, whitespace, non-ASCII, `.`/`..` segments, empty segments, trailing slash.
4. **No redirects.** `redirects(0)`; any 3xx is refused, never followed.
5. **No retries.** One request per invocation; 4xx/5xx surfaced once.
6. **Path denylist.** Refused locally before any request if any path segment, split on non-alphanumerics and lowercased, has a token equal to or starting with: `accept`, `decline`, `invite`, `invitation`, `join`, `token`, `rotate`, `rotation`, `delete`, `archive`, `close`, `submit`, `submission`, `mark`, `export`. A handle such as `remarkable` or `bookmark` is allowed (`mark` is not a prefix); `mark-read`, `invitations`, `submissions` are refused. `EXPLICIT_DENY` (full-path regexes, checked first) contains `^/v1/hackers/report_intents/[^/]+/submit$`, `^/v1/hackers/report_intents/[^/]+/attachments/.+`, and `^/v1/hackers/reports$`. The attachments collection GET has nothing after `attachments` and stays allowed; a further id is the documented DELETE and is refused. `GET /v1/hackers/reports/{id}` stays allowed. Paths longer than 1024 bytes are refused without echoing the whole value.
7. **Query parameters.** Names must be JSON:API shaped (`name`, `name[sub]`, `name[sub__op]`; ASCII identifiers starting with a letter) and are checked against the same denylist; unknown/odd names, missing `=`, and duplicate names are refused. At most 16 parameters. Values must be ASCII, at most 2048 characters, and may contain spaces but not other whitespace or control characters. `build_request` repeats these checks. Names and values are strictly percent-encoded (only unreserved characters pass), so a value cannot inject `&`, `#`, `/`, or CR/LF. The finished URL is capped at 8192 bytes.
8. **JSON only.** A response whose body is not valid JSON, or whose Content-Type is missing or not `application/json`, `application/vnd.api+json`, `text/json` or `*+json`, is refused and its body is not printed (success and error paths). The displayed content-type is a short token; a header containing a newline is not echoed.
9. **Token handling.** Read from `H1_API_TOKEN` only (required; no CLI arg exists for it), never printed: `Debug` is redacted, `--dry-run` prints the URL, username and "present/NOT SET", and every stdout/stderr write is scrubbed of the token, its percent-encoding (when the token is at least 8 characters), and its Basic-auth base64 form. Username (`H1_API_USERNAME`, default `jcwilk`) must be ASCII, 1–64 characters, with no `:` or whitespace. The token must be ASCII, at most 1024 characters, with no control characters.
10. **No environment influence.** The only env vars read are `H1_API_TOKEN` and `H1_API_USERNAME` (enforced by a test). No proxy, host, method or redirect setting can be changed from outside.
11. **Size cap.** Response bodies over 8 MiB are refused.

## Subcommand safety notes

- A subcommand only formats a path from one argument (`handle` or numeric `id`) and documented read params (`--limit`/`--page`, hacktivity `--query`/`--sort`, scope `--since-id`/`--created-after`/`--updated-after`). `intents` sends no query string. The builder also rejects arguments that are not a single `[A-Za-z0-9_.~-]` segment (report and intent ids must be digits, so `1/submit` cannot be built), but this is a second layer: the **validator** independently refuses `../invitations`, `x/submit`, `%2e%2e`, `a b`, `a?b`, URLs, backslashes, control characters, denylisted words, the submit path, and any path under `report_intents/<id>/attachments/<id>`, and `build_request` re-validates and re-checks the host/prefix lock. Tests cover both layers. `--query` is one parameter: `&` and `=` inside it are percent-encoded and cannot add another parameter. `--sort` accepts only the documented hacktivity fields.
- Subcommand flags cannot influence verb, host, redirects or headers; `--fields`/`--max-chars`/`--bounty-only` only affect local rendering. `cmd.rs` and `render.rs` contain no network, env, filesystem or process access (source-scan test).
- `/v1/hackers/me` is not a subcommand. A Hacker API token gets 401 there, and the catalog does not list it. `h1ro raw /v1/hackers/me` still performs that GET if you ask for it.

## Differences from the Python version

- Raw-path mode output is pretty-printed (Python echoed the raw body); percent-encoding in paths is rejected; non-ASCII/whitespace rejected; duplicate query names refused; unknown dash options refused; `--dry-run` added; HTTP errors exit 1 (as Python's `SystemExit(str)` did).

## Docs review (2026-11-09)

Sources: [Hacker Resources](https://api.hackerone.com/hacker-resources/), [Getting Started](https://api.hackerone.com/getting-started-hacker-api/), and the [Hacker Reference](https://api.hackerone.com/hacker-reference/) object schemas. The Hacker Resources page is the endpoint catalog.

### Documented GET endpoints

All of the following are described as fetches of existing data (lists, a single object, or a balance). None of the public docs describe a write side effect for GET — no marking items read, no token generate/rotate, no triggering an export, and no accepting or declining an invite via GET.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/hackers/hacktivity` | Paginated public hacktivity |
| GET | `/v1/hackers/me/reports` | The caller's reports |
| GET | `/v1/hackers/reports/{id}` | A single report (stats, activities, etc.) |
| GET | `/v1/hackers/payments/balance` | Balance |
| GET | `/v1/hackers/payments/earnings` | Earnings |
| GET | `/v1/hackers/payments/payouts` | Payouts |
| GET | `/v1/hackers/programs` | Programs visible to the caller |
| GET | `/v1/hackers/programs/{handle}` | One program |
| GET | `/v1/hackers/programs/{handle}/structured_scopes` | Scope assets |
| GET | `/v1/hackers/programs/{handle}/weaknesses` | Program weaknesses |
| GET | `/v1/hackers/programs/{handle}/scope_exclusions` | Reward-excluded categories |
| GET | `/v1/hackers/report_intents` | The caller's report intents (drafts) |
| GET | `/v1/hackers/report_intents/{id}` | One report intent |
| GET | `/v1/hackers/report_intents/{id}/attachments` | Attachments on a report intent |

`/v1/hackers/me/programs` is **not** listed in the current Hacker Resources catalog (the documented collection path is `/v1/hackers/programs`). The wrapper still allows `me/programs` as a GET under `/v1/hackers`, because it may be a supported alias and is a natural "my programs" path.

Getting Started states that the API always returns JSON, uses HTTPS only, and is JSON:API compliant. Rate limits: 600 reads/minute, 25 writes/20 seconds, and 50/minute on structured scopes. Writes are irrelevant here because this wrapper never issues them.

### Documented write endpoints (blocked by GET-only; submit also denylisted)

| Method | Path |
| --- | --- |
| POST | `/v1/hackers/reports` (create/submit a report) |
| POST | `/v1/hackers/report_intents` |
| PATCH | `/v1/hackers/report_intents/{id}` |
| DELETE | `/v1/hackers/report_intents/{id}` |
| POST | `/v1/hackers/report_intents/{id}/submit` |
| POST | `/v1/hackers/report_intents/{id}/attachments` |
| DELETE | `/v1/hackers/report_intents/{id}/attachments/{id}` |

The Getting Started changelog also mentions older "create asset enrichment submissions" and "bulk create hacker asset submissions" endpoints. Those entries are no longer in the Hacker Resources navigation; they were documented as create/write operations, not GETs. A path segment containing `submit` would still be refused.

Inviting hackers, listing program invitations, archiving assets, and similar actions appear on the *customer* (program) API, not the Hacker API, and use paths outside `/v1/hackers` (which this wrapper already refuses).

### Finding

**No documented Hacker API GET endpoint has write side effects.** Every catalog GET above is a subcommand, except the create-report URL `GET /v1/hackers/reports` (no id), which is refused because that path is the documented POST. `GET /v1/hackers/reports/{id}` stays allowed. Hacktivity `queryString` and `sort`, and the structured-scope `filter[id__gt]` / `filter[created_at__gt]` / `filter[updated_at__gt]` parameters, are flags on those GETs. The denylist still blocks action-looking path segments, the `/submit` write suffix, and any path under `report_intents/{id}/attachments/{id}` (the documented DELETE). The customer-API bounty table (`GET /v1/programs/{id}/bounty_table`) stays outside the `/v1/hackers` prefix lock. Attachment bytes are on `expiring_url` hosts and are not requested.

Rechecked against the Hacker Resources catalog on 2026-11-10.

## Tests

```bash
cd /workspace/tools/h1ro
cargo test          # 71 offline tests; no network
cargo build --release && cp target/release/h1ro ./h1ro
```

`/home/box/bin/h1ro` is a symlink to `/workspace/tools/h1ro/h1ro`. Tests use a fake `Transport`; they never call api.hackerone.com. Source layout: `lib.rs` (validators, request builder, credentials, `perform`), `http.rs` (the only network code), `cmd.rs` (subcommands/help/planning/footers), `render.rs` (compact tables), `main.rs` (mode dispatch), `tests.rs` + `cmd_tests.rs`.
