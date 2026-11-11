//! Agent-facing subcommand layer.
//!
//! Subcommands are only ergonomic path/param BUILDERS. Every request they produce goes through
//! the same `validate_path` / `validate_params` / `build_request` (lib.rs) and the same
//! `perform` (GET-only transport). The builders contain no network code, read no environment,
//! and a path outside `/v1/hackers` cannot be produced because `build_request` refuses it.

use crate::render::*;
use crate::{
    build_request, dry_run_text, perform, validate_params, validate_path, Credentials, Outcome,
    Refused, Transport, ValidatedRequest,
};
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    ProgramsList,
    ProgramsGet,
    ProgramsScopes,
    ProgramsWeaknesses,
    ProgramsExclusions,
    ReportsList,
    ReportsGet,
    Me,
    Hacktivity,
    PaymentsBalance,
    PaymentsEarnings,
    PaymentsPayouts,
    IntentsList,
    IntentsGet,
    IntentsAttachments,
    Raw,
}

pub struct Spec {
    pub name: &'static str,
    pub kind: Kind,
    pub summary: &'static str,
    pub usage: &'static str,
    pub endpoint: &'static str,
    pub columns: &'static str,
    pub notes: &'static str,
    pub example: &'static str,
    pub flags: &'static [&'static str],
}

const LIST_FLAGS: &[&str] = &["--json", "--dry-run", "--limit", "--page", "--fields", "--max-chars"];
const GET_FLAGS: &[&str] = &["--json", "--dry-run", "--max-chars"];
/// List rendering without pagination params. Report-intent GETs do not document page[].
const READ_LIST_FLAGS: &[&str] = &["--json", "--dry-run", "--fields", "--max-chars"];
const HACKTIVITY_FLAGS: &[&str] = &[
    "--json", "--dry-run", "--limit", "--page", "--fields", "--max-chars", "--query", "--sort",
];
const SCOPE_FLAGS: &[&str] = &[
    "--json",
    "--dry-run",
    "--limit",
    "--page",
    "--fields",
    "--max-chars",
    "--since-id",
    "--created-after",
    "--updated-after",
];

/// Documented `sort` values for GET /v1/hackers/hacktivity. Anything else is refused.
const HACKTIVITY_SORTS: &[&str] = &[
    "latest_disclosable_activity_at",
    "-latest_disclosable_activity_at",
    "disclosed_at",
    "-disclosed_at",
    "total_awarded_amount",
    "-total_awarded_amount",
    "votes",
    "-votes",
];

pub const SPECS: &[Spec] = &[
    Spec {
        name: "programs list",
        kind: Kind::ProgramsList,
        summary: "programs visible to you (handle, name, bounty, state)",
        usage: "h1ro programs list [--bounty-only] [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/programs[?page[size]=N&page[number]=N]",
        columns: "handle, name, offers_bounties, state, submission_state",
        notes: "--bounty-only filters CLIENT-SIDE (offers_bounties=true) on the fetched page only; the API returns all programs, so page through with --page. Ignored with --json (full unfiltered JSON).",
        example: "h1ro programs list --bounty-only --limit 100 --page 2",
        flags: &["--json", "--dry-run", "--limit", "--page", "--fields", "--max-chars", "--bounty-only"],
    },
    Spec {
        name: "programs get",
        kind: Kind::ProgramsGet,
        summary: "one program's attributes (policy truncated)",
        usage: "h1ro programs get <handle> [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/programs/<handle>",
        columns: "key<TAB>value lines: id, type, then every attribute in API order",
        notes: "Long fields (policy) are cut at --max-chars (default 200) with a `…[+N chars]` marker; use --json or --max-chars 0 for everything.",
        example: "h1ro programs get dyson",
        flags: GET_FLAGS,
    },
    Spec {
        name: "programs scopes",
        kind: Kind::ProgramsScopes,
        summary: "a program's structured scope assets",
        usage: "h1ro programs scopes <handle> [--since-id N] [--created-after ISO] [--updated-after ISO] [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/programs/<handle>/structured_scopes[?filter[id__gt]=N&filter[created_at__gt]=ISO&filter[updated_at__gt]=ISO&page[size]=N&page[number]=N]",
        columns: "asset_type, asset_identifier, eligible_for_bounty, eligible_for_submission, max_severity",
        notes: "Other selectable fields include instruction, created_at, updated_at, confidentiality_requirement. API rate limit: 50/min. Pagination stops at 10,000 rows; --since-id sends filter[id__gt] (results are ordered by id) and --created-after/--updated-after send the documented ISO-8601 filters. These are read filters only.",
        example: "h1ro programs scopes dyson --limit 100 --since-id 9012",
        flags: SCOPE_FLAGS,
    },
    Spec {
        name: "programs weaknesses",
        kind: Kind::ProgramsWeaknesses,
        summary: "weaknesses (CWE) a program accepts",
        usage: "h1ro programs weaknesses <handle> [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/programs/<handle>/weaknesses[?page[size]=N&page[number]=N]",
        columns: "id, name, external_id (description available via --fields)",
        notes: "",
        example: "h1ro programs weaknesses dyson --limit 50",
        flags: LIST_FLAGS,
    },
    Spec {
        name: "programs exclusions",
        kind: Kind::ProgramsExclusions,
        summary: "a program's reward-excluded scope categories",
        usage: "h1ro programs exclusions <handle> [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/programs/<handle>/scope_exclusions[?page[size]=N&page[number]=N]",
        columns: "auto: id + up to 6 scalar attributes of the first record (list may be empty)",
        notes: "",
        example: "h1ro programs exclusions dyson",
        flags: LIST_FLAGS,
    },
    Spec {
        name: "reports list",
        kind: Kind::ReportsList,
        summary: "your own reports",
        usage: "h1ro reports list [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/me/reports[?page[size]=N&page[number]=N]",
        columns: "id, state, created_at, bounty_awarded_at, title, program",
        notes: "Titles are truncated at --max-chars (default 80). Report bodies (vulnerability_information) are only in --json or `reports get`.",
        example: "h1ro reports list --limit 25",
        flags: LIST_FLAGS,
    },
    Spec {
        name: "reports get",
        kind: Kind::ReportsGet,
        summary: "one report by numeric id (body truncated)",
        usage: "h1ro reports get <id> [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/reports/<id>",
        columns: "key<TAB>value lines: id, type, then every attribute in API order; then an activities table (created_at, type, actor, message) when the report includes one. Other relationships are named in the stderr footer; full data via --json",
        notes: "<id> must be digits only. Activities are the ones already embedded in this GET. Attachment files and expiring_url values are not requested.",
        example: "h1ro reports get 4149145 --max-chars 0",
        flags: GET_FLAGS,
    },
    Spec {
        name: "me",
        kind: Kind::Me,
        summary: "GET /v1/hackers/me (may 401 for this token type)",
        usage: "h1ro me [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/me",
        columns: "key<TAB>value lines",
        notes: "NOTE: this may 401 (it has returned \"not a Customer API token\" for the Hacker API token); the error is surfaced as `error: HTTP 401: ...`. Use `programs list` as the liveness check instead.",
        example: "h1ro me --json",
        flags: GET_FLAGS,
    },
    Spec {
        name: "hacktivity",
        kind: Kind::Hacktivity,
        summary: "public hacktivity feed",
        usage: "h1ro hacktivity [--query LUCENE] [--sort FIELD] [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/hacktivity[?queryString=LUCENE&sort=FIELD&page[size]=N&page[number]=N]",
        columns: "id, submitted_at, disclosed, title, severity_rating, total_awarded_amount, substate, program",
        notes: "--query is the documented Lucene queryString (severity_rating, asset_type, substate, cwe, cve_ids, reporter, team, total_awarded_amount, disclosed_at, has_collaboration, disclosed). It is one query parameter, percent-encoded, and cannot add further parameters. --sort is one of latest_disclosable_activity_at, disclosed_at, total_awarded_amount, votes, with an optional leading - for descending. Many fields are null for undisclosed items. program is the included program handle.",
        example: "h1ro hacktivity --query 'severity_rating:critical AND disclosed:true' --sort -disclosed_at --limit 20",
        flags: HACKTIVITY_FLAGS,
    },
    Spec {
        name: "payments balance",
        kind: Kind::PaymentsBalance,
        summary: "your payout balance",
        usage: "h1ro payments balance [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/payments/balance",
        columns: "key<TAB>value lines",
        notes: "",
        example: "h1ro payments balance",
        flags: GET_FLAGS,
    },
    Spec {
        name: "payments earnings",
        kind: Kind::PaymentsEarnings,
        summary: "your earnings",
        usage: "h1ro payments earnings [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/payments/earnings[?page[size]=N&page[number]=N]",
        columns: "auto: id + up to 6 scalar attributes of the first record (list may be empty)",
        notes: "",
        example: "h1ro payments earnings",
        flags: LIST_FLAGS,
    },
    Spec {
        name: "payments payouts",
        kind: Kind::PaymentsPayouts,
        summary: "your payouts",
        usage: "h1ro payments payouts [--limit N] [--page N] [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/payments/payouts[?page[size]=N&page[number]=N]",
        columns: "auto: id + up to 6 scalar attributes of the first record (list may be empty)",
        notes: "",
        example: "h1ro payments payouts",
        flags: LIST_FLAGS,
    },
    Spec {
        name: "intents list",
        kind: Kind::IntentsList,
        summary: "your report drafts",
        usage: "h1ro intents list [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/report_intents",
        columns: "id, state, title",
        notes: "Read-only list of drafts you created. The catalog documents no query parameters for this GET, so this command sends none. Submit, update, and delete exist only as POST, PATCH, and DELETE and are not commands.",
        example: "h1ro intents list",
        flags: READ_LIST_FLAGS,
    },
    Spec {
        name: "intents get",
        kind: Kind::IntentsGet,
        summary: "one report draft by numeric id",
        usage: "h1ro intents get <id> [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/report_intents/<id>",
        columns: "key<TAB>value lines: id, type, then every attribute in API order",
        notes: "<id> must be digits only. The same path is the PATCH/DELETE url; this command sends GET and no body. /submit is refused.",
        example: "h1ro intents get 23",
        flags: GET_FLAGS,
    },
    Spec {
        name: "intents attachments",
        kind: Kind::IntentsAttachments,
        summary: "attachment metadata on one report draft",
        usage: "h1ro intents attachments <id> [--fields a,b] [--max-chars N] [--json] [--dry-run]",
        endpoint: "GET /v1/hackers/report_intents/<id>/attachments",
        columns: "id, file_name, content_type, file_size, created_at",
        notes: "Collection GET only. The catalog documents no query parameters, so this command sends none. A further attachment id is the DELETE url and is refused locally. expiring_url stays in --json only and is never requested.",
        example: "h1ro intents attachments 23",
        flags: READ_LIST_FLAGS,
    },
    Spec {
        name: "raw",
        kind: Kind::Raw,
        summary: "any allowed GET under /v1/hackers (escape hatch)",
        usage: "h1ro raw </v1/hackers/...> [key=value ...] [--json] [--dry-run]",
        endpoint: "GET <path>[?key=value&...], path must be /v1/hackers or /v1/hackers/<segments>",
        columns: "pretty-printed JSON (always; --json is accepted as a no-op)",
        notes: "Same validator as every other command (host/prefix lock, denylist, explicit submit and per-attachment denies). Equivalent legacy form: h1ro /v1/hackers/... key=value",
        example: "h1ro raw /v1/hackers/programs/dyson/weaknesses 'page[size]=5'",
        flags: &["--json", "--dry-run"],
    },
];

pub const GROUPS: &[(&str, &str)] = &[
    ("programs", "list | get | scopes | weaknesses | exclusions"),
    ("reports", "list | get"),
    ("payments", "balance | earnings | payouts"),
    ("intents", "list | get | attachments"),
];

pub const OVERVIEW: &str = "\
h1ro - read-only HackerOne Hacker API client. GET only, https://api.hackerone.com/v1/hackers/* only.
usage: h1ro <command> [args] [flags]     raw path mode: h1ro /v1/hackers/... [key=value ...] [--dry-run]
commands:
  programs    list|get|scopes|weaknesses|exclusions   programs you can see; one program; its scope/weaknesses
  reports     list|get                                your reports; one report, including its activities
  payments    balance|earnings|payouts                your payments
  intents     list|get|attachments                    your report drafts and their attachment metadata
  hacktivity                                          public hacktivity (--query, --sort)
  me                                                  GET /v1/hackers/me (may 401 for this token)
  raw <path> [k=v ...]                                any allowed GET under /v1/hackers
  help [command]                                      this overview, or help for a command
global flags: --json (full pretty JSON)  --dry-run (print the GET, no network)  --help
list flags:   --limit N (page[size], 1-100)  --page N  --fields a,b,c  --max-chars N (0=no truncation)
read filters: hacktivity --query <lucene> --sort <field>; scopes --since-id N --created-after <iso> --updated-after <iso>
stdout = data only; stderr = footer/errors (`error:` / `refused:`). Env: H1_API_TOKEN, H1_API_USERNAME (default jcwilk).
details: h1ro <command> --help   (shows the exact GET endpoint)
";

const FLAG_HELP: &[(&str, &str)] = &[
    ("--json", "full response as pretty JSON (no truncation)"),
    ("--dry-run", "print the exact GET it WOULD make; no network call, token hidden"),
    ("--limit", "N=1..100, maps to page[size]=N"),
    ("--page", "N>=1, maps to page[number]=N"),
    ("--fields", "a,b,c  choose compact columns (any attribute name, or id)"),
    ("--max-chars", "N  truncate each compact cell at N chars (0 = never); default 80 lists / 200 get"),
    ("--bounty-only", "client-side filter: keep offers_bounties=true rows of the fetched page"),
    ("--query", "Lucene queryString for hacktivity (one encoded parameter)"),
    ("--sort", "hacktivity sort: disclosed_at, votes, total_awarded_amount, latest_disclosable_activity_at; prefix - for descending"),
    ("--since-id", "N  structured scopes with id greater than N (filter[id__gt])"),
    ("--created-after", "ISO-8601  structured scopes created after this time (filter[created_at__gt])"),
    ("--updated-after", "ISO-8601  structured scopes updated after this time (filter[updated_at__gt])"),
];

pub fn spec_help(s: &Spec) -> String {
    let mut o = format!("{}\n{}\n", s.usage, s.endpoint);
    o.push_str(&format!("output:  {}\n", s.columns));
    let flags: Vec<&str> = s.flags.iter().copied().collect();
    for (f, d) in FLAG_HELP {
        if flags.contains(f) {
            o.push_str(&format!("  {f:<16} {d}\n"));
        }
    }
    if !s.notes.is_empty() {
        o.push_str(&format!("note: {}\n", s.notes));
    }
    o.push_str(&format!("example: {}\n", s.example));
    o
}

pub fn group_listing(group: &str) -> String {
    let mut o = format!("h1ro {group} <subcommand>   (h1ro {group} <subcommand> --help for details)\n");
    for s in SPECS {
        if let Some(sub) = s.name.strip_prefix(&format!("{group} ")) {
            o.push_str(&format!("  {sub:<11} {}\n", s.summary));
        }
    }
    o
}

// ---------------------------------------------------------------- option parsing

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Opts {
    pub json: bool,
    pub dry_run: bool,
    pub help: bool,
    pub bounty_only: bool,
    pub limit: Option<u32>,
    pub page: Option<u32>,
    pub fields: Option<Vec<String>>,
    pub max_chars: Option<usize>,
    pub query: Option<String>,
    pub sort: Option<String>,
    pub since_id: Option<u64>,
    pub created_after: Option<String>,
    pub updated_after: Option<String>,
    /// Flag names seen, e.g. "--limit".
    pub used: Vec<&'static str>,
    pub pos: Vec<String>,
}

fn usage_err<T>(msg: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(format!("error: {}", msg.into())))
}

const VALUE_FLAGS: [&str; 9] = [
    "--limit",
    "--page",
    "--fields",
    "--max-chars",
    "--query",
    "--sort",
    "--since-id",
    "--created-after",
    "--updated-after",
];
const BOOL_FLAGS: [&str; 4] = ["--json", "--dry-run", "--bounty-only", "--help"];

fn static_flag(name: &str) -> Option<&'static str> {
    VALUE_FLAGS
        .iter()
        .chain(BOOL_FLAGS.iter())
        .find(|f| **f == name)
        .copied()
}

fn parse_num(flag: &str, v: &str, min: u64, max: u64) -> Result<u64, Refused> {
    match v.parse::<u64>() {
        Ok(n) if n >= min && n <= max => Ok(n),
        _ => usage_err(format!("{flag} expects an integer {min}..{max}, got '{v}'")),
    }
}

fn check_query(v: &str) -> Result<(), Refused> {
    if v.is_empty() || v.chars().all(|c| c.is_whitespace()) {
        return usage_err("--query requires a Lucene query string");
    }
    if v.chars().count() > 1024 {
        return usage_err("--query is limited to 1024 characters");
    }
    if v.chars().any(|c| c.is_control()) {
        return usage_err("--query contains control characters");
    }
    Ok(())
}

fn check_sort(v: &str) -> Result<(), Refused> {
    if HACKTIVITY_SORTS.contains(&v) {
        Ok(())
    } else {
        usage_err(format!(
            "--sort must be one of {} (prefix - for descending), got '{v}'",
            HACKTIVITY_SORTS.join(", ")
        ))
    }
}

/// Documented structured-scope timestamps: a calendar date, or a full time with Z or ±hh:mm.
fn iso8601_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() == 10 {
        return date_prefix(b);
    }
    if b.len() < 20 || b.len() > 35 || !date_prefix(b) || b[10] != b'T' {
        return false;
    }
    if !(digits(b, 11, 2) && b[13] == b':' && digits(b, 14, 2) && b[16] == b':' && digits(b, 17, 2)) {
        return false;
    }
    let mut i = 19;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || i - start > 9 {
            return false;
        }
    }
    if i >= b.len() {
        return false;
    }
    if b[i] == b'Z' {
        return i + 1 == b.len();
    }
    if b[i] == b'+' || b[i] == b'-' {
        let rest = &b[i + 1..];
        return rest.len() == 5 && digits(rest, 0, 2) && rest[2] == b':' && digits(rest, 3, 2);
    }
    false
}

fn date_prefix(b: &[u8]) -> bool {
    b.len() >= 10
        && digits(b, 0, 4)
        && b[4] == b'-'
        && digits(b, 5, 2)
        && b[7] == b'-'
        && digits(b, 8, 2)
}

fn digits(b: &[u8], at: usize, n: usize) -> bool {
    b.get(at..at + n).is_some_and(|s| s.iter().all(|c| c.is_ascii_digit()))
}

fn check_iso(flag: &str, v: &str) -> Result<(), Refused> {
    if iso8601_ok(v) {
        Ok(())
    } else {
        usage_err(format!(
            "{flag} expects YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, got '{v}'"
        ))
    }
}

pub fn parse_opts(args: &[String]) -> Result<Opts, Refused> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "-h" {
            o.help = true;
            continue;
        }
        if !a.starts_with('-') || a == "-" {
            o.pos.push(a.clone());
            continue;
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (a.as_str(), None),
        };
        let flag = match static_flag(name) {
            Some(f) => f,
            None => return usage_err(format!("unknown option: {name}")),
        };
        if BOOL_FLAGS.contains(&flag) {
            if inline.is_some() {
                return usage_err(format!("{flag} takes no value"));
            }
            match flag {
                "--json" => o.json = true,
                "--dry-run" => o.dry_run = true,
                "--bounty-only" => o.bounty_only = true,
                _ => o.help = true,
            }
        } else {
            let val = match inline {
                Some(v) => v,
                None => {
                    if i >= args.len() {
                        return usage_err(format!("{flag} requires a value"));
                    }
                    i += 1;
                    args[i - 1].clone()
                }
            };
            match flag {
                "--limit" => o.limit = Some(parse_num(flag, &val, 1, 100)? as u32),
                "--page" => o.page = Some(parse_num(flag, &val, 1, 1_000_000)? as u32),
                "--max-chars" => o.max_chars = Some(parse_num(flag, &val, 0, 1_000_000)? as usize),
                "--query" => {
                    check_query(&val)?;
                    o.query = Some(val);
                }
                "--sort" => {
                    check_sort(&val)?;
                    o.sort = Some(val);
                }
                "--since-id" => o.since_id = Some(parse_num(flag, &val, 0, 1_000_000_000_000)?),
                "--created-after" => {
                    check_iso(flag, &val)?;
                    o.created_after = Some(val);
                }
                "--updated-after" => {
                    check_iso(flag, &val)?;
                    o.updated_after = Some(val);
                }
                _ => {
                    let fields: Vec<String> = val.split(',').map(str::to_string).collect();
                    if fields.iter().any(|f| {
                        f.is_empty() || !f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    }) {
                        return usage_err(format!("--fields expects a,b,c of [A-Za-z0-9_] names, got '{val}'"));
                    }
                    o.fields = Some(fields);
                }
            }
        }
        if !o.used.contains(&flag) {
            o.used.push(flag);
        }
    }
    Ok(o)
}

// ---------------------------------------------------------------- planning

#[derive(Debug)]
pub struct RequestPlan {
    pub kind: Kind,
    pub name: &'static str,
    pub req: ValidatedRequest,
    pub path: String,
    /// Canonical command text for next-page hints, e.g. "programs scopes dyson".
    pub label: String,
    pub opts: Opts,
}

#[derive(Debug)]
pub enum Plan {
    /// Help/listing text to print on stdout (exit 0).
    Text(String),
    Request(Box<RequestPlan>),
}

/// Pure formatter: the API path a command maps to for its single argument. Performs NO checking;
/// callers MUST pass the result through `validate_path` (the plan builder does, and tests prove the
/// validator refuses hostile arguments independently of any builder check).
pub fn path_for(kind: Kind, arg: &str) -> String {
    match kind {
        Kind::ProgramsList => "/v1/hackers/programs".into(),
        Kind::ProgramsGet => format!("/v1/hackers/programs/{arg}"),
        Kind::ProgramsScopes => format!("/v1/hackers/programs/{arg}/structured_scopes"),
        Kind::ProgramsWeaknesses => format!("/v1/hackers/programs/{arg}/weaknesses"),
        Kind::ProgramsExclusions => format!("/v1/hackers/programs/{arg}/scope_exclusions"),
        Kind::ReportsList => "/v1/hackers/me/reports".into(),
        Kind::ReportsGet => format!("/v1/hackers/reports/{arg}"),
        Kind::Me => "/v1/hackers/me".into(),
        Kind::Hacktivity => "/v1/hackers/hacktivity".into(),
        Kind::PaymentsBalance => "/v1/hackers/payments/balance".into(),
        Kind::PaymentsEarnings => "/v1/hackers/payments/earnings".into(),
        Kind::PaymentsPayouts => "/v1/hackers/payments/payouts".into(),
        Kind::IntentsList => "/v1/hackers/report_intents".into(),
        Kind::IntentsGet => format!("/v1/hackers/report_intents/{arg}"),
        Kind::IntentsAttachments => format!("/v1/hackers/report_intents/{arg}/attachments"),
        Kind::Raw => arg.to_string(),
    }
}

fn takes_arg(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::ProgramsGet
            | Kind::ProgramsScopes
            | Kind::ProgramsWeaknesses
            | Kind::ProgramsExclusions
            | Kind::ReportsGet
            | Kind::IntentsGet
            | Kind::IntentsAttachments
    )
}

/// Builder-side sanity check (extra layer; the validator remains the enforcement point).
fn check_arg(kind: Kind, what: &str, arg: &str) -> Result<(), Refused> {
    let numeric = matches!(kind, Kind::ReportsGet | Kind::IntentsGet | Kind::IntentsAttachments);
    let ok = !arg.is_empty()
        && if numeric {
            arg.len() <= 20 && arg.chars().all(|c| c.is_ascii_digit())
        } else {
            arg != "." && arg != ".."
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '~' | '-'))
        };
    if ok {
        Ok(())
    } else {
        Err(Refused(format!(
            "refused: invalid {what} '{}' (must be a single {} segment)",
            arg.chars().take(60).collect::<String>(),
            if numeric { "numeric" } else { "[A-Za-z0-9_.~-]" }
        )))
    }
}

fn find_spec(name: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|s| s.name == name)
}

/// Turn args (everything after argv[0]) into a plan. Pure: no I/O, no env, no network.
pub fn plan(args: &[String]) -> Result<Plan, Refused> {
    let o = parse_opts(args)?;
    if o.pos.is_empty() {
        return if args.is_empty() || o.help {
            Ok(Plan::Text(OVERVIEW.to_string()))
        } else {
            usage_err("command required (h1ro --help)")
        };
    }
    let first = o.pos[0].as_str();
    if first == "help" {
        return Ok(Plan::Text(help_for(&o.pos[1..])));
    }
    // Resolve "<group> <sub>" or a leaf.
    let (spec, rest): (&'static Spec, &[String]) = if GROUPS.iter().any(|(g, _)| *g == first) {
        if o.pos.len() < 2 {
            return Ok(Plan::Text(group_listing(first)));
        }
        match find_spec(&format!("{first} {}", o.pos[1])) {
            Some(s) => (s, &o.pos[2..]),
            None => {
                return usage_err(format!(
                    "unknown subcommand '{first} {}'\n{}",
                    o.pos[1].chars().take(40).collect::<String>(),
                    group_listing(first).trim_end()
                ))
            }
        }
    } else {
        match find_spec(first) {
            Some(s) => (s, &o.pos[1..]),
            None => {
                return usage_err(format!(
                    "unknown command '{}' (h1ro --help lists commands)",
                    first.chars().take(40).collect::<String>()
                ))
            }
        }
    };
    if o.help {
        return Ok(Plan::Text(spec_help(spec)));
    }
    for f in &o.used {
        if !spec.flags.contains(f) {
            return usage_err(format!(
                "option {f} is not valid for '{}' (valid: {})",
                spec.name,
                spec.flags.join(" ")
            ));
        }
    }
    // Argument shape.
    let mut params: Vec<String> = Vec::new();
    let (arg, label): (String, String) = if spec.kind == Kind::Raw {
        if rest.is_empty() {
            return usage_err("raw requires a path: h1ro raw /v1/hackers/... [key=value ...]");
        }
        params.extend(rest[1..].iter().cloned());
        (rest[0].clone(), format!("raw {}", rest[0]))
    } else if takes_arg(spec.kind) {
        let what = if matches!(
            spec.kind,
            Kind::ReportsGet | Kind::IntentsGet | Kind::IntentsAttachments
        ) {
            "id"
        } else {
            "handle"
        };
        if rest.len() != 1 {
            return usage_err(format!("'{}' takes exactly one <{what}>: {}", spec.name, spec.usage));
        }
        check_arg(spec.kind, what, &rest[0])?;
        (rest[0].clone(), format!("{} {}", spec.name, rest[0]))
    } else {
        if !rest.is_empty() {
            return usage_err(format!("'{}' takes no arguments: {}", spec.name, spec.usage));
        }
        (String::new(), spec.name.to_string())
    };
    if let Some(q) = &o.query {
        params.push(format!("queryString={q}"));
    }
    if let Some(s) = &o.sort {
        params.push(format!("sort={s}"));
    }
    if let Some(n) = o.since_id {
        params.push(format!("filter[id__gt]={n}"));
    }
    if let Some(t) = &o.created_after {
        params.push(format!("filter[created_at__gt]={t}"));
    }
    if let Some(t) = &o.updated_after {
        params.push(format!("filter[updated_at__gt]={t}"));
    }
    if let Some(n) = o.limit {
        params.push(format!("page[size]={n}"));
    }
    if let Some(n) = o.page {
        params.push(format!("page[number]={n}"));
    }
    // Everything below is the SAME validator the raw path mode uses.
    let path = validate_path(&path_for(spec.kind, &arg))?;
    let pairs = validate_params(&params)?;
    let req = build_request(&path, &pairs)?;
    Ok(Plan::Request(Box::new(RequestPlan {
        kind: spec.kind,
        name: spec.name,
        req,
        path,
        label,
        opts: o,
    })))
}

fn help_for(rest: &[String]) -> String {
    if rest.is_empty() {
        return OVERVIEW.to_string();
    }
    let first = rest[0].as_str();
    if GROUPS.iter().any(|(g, _)| *g == first) {
        if let Some(sub) = rest.get(1) {
            if let Some(s) = find_spec(&format!("{first} {sub}")) {
                return spec_help(s);
            }
        }
        return group_listing(first);
    }
    match find_spec(first) {
        Some(s) => spec_help(s),
        None => format!("error: unknown command '{}'\n{OVERVIEW}", first.chars().take(40).collect::<String>()),
    }
}

// ---------------------------------------------------------------- execution

fn default_columns(kind: Kind) -> Option<&'static [&'static str]> {
    match kind {
        Kind::ProgramsList => Some(&["handle", "name", "offers_bounties", "state", "submission_state"]),
        Kind::ProgramsScopes => Some(&[
            "asset_type",
            "asset_identifier",
            "eligible_for_bounty",
            "eligible_for_submission",
            "max_severity",
        ]),
        Kind::ProgramsWeaknesses => Some(&["id", "name", "external_id"]),
        Kind::ReportsList => Some(&["id", "state", "created_at", "bounty_awarded_at", "title", "program"]),
        Kind::Hacktivity => Some(&[
            "id",
            "submitted_at",
            "disclosed",
            "title",
            "severity_rating",
            "total_awarded_amount",
            "substate",
            "program",
        ]),
        Kind::IntentsList => Some(&["id", "state", "title"]),
        Kind::IntentsAttachments => Some(&["id", "file_name", "content_type", "file_size", "created_at"]),
        _ => None,
    }
}

fn is_list(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::ProgramsList
            | Kind::ProgramsScopes
            | Kind::ProgramsWeaknesses
            | Kind::ProgramsExclusions
            | Kind::ReportsList
            | Kind::Hacktivity
            | Kind::PaymentsEarnings
            | Kind::PaymentsPayouts
            | Kind::IntentsList
            | Kind::IntentsAttachments
    )
}

fn shell_quote(s: &str) -> String {
    // Controls would break the one-line footer even inside quotes if a consumer
    // copies a single physical line. They are already refused in query values.
    let flat: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if flat.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-' | '=' | ':')) {
        flat
    } else {
        format!("'{}'", flat.replace('\'', r"'\''"))
    }
}

/// Footer for list commands (goes to stderr): what you are looking at + the exact next command.
fn list_footer(p: &RequestPlan, v: &Value, rows: usize, kept: Option<usize>, trunc: usize, max: usize) -> String {
    let info = page_info(v, p.opts.page, p.opts.limit);
    let mut parts: Vec<String> = Vec::new();
    match kept {
        Some(k) => parts.push(format!(
            "{k} of {rows} rows kept (--bounty-only is a client-side filter of this page; API returns all programs)"
        )),
        None => parts.push(format!("{rows} rows")),
    }
    let size = match info.size {
        Some(s) => format!("size {s}"),
        None => "size: API default, not reported".to_string(),
    };
    parts.push(match info.last {
        Some(l) => format!("page {} of {l} ({size})", info.page),
        None => format!("page {} ({size})", info.page),
    });
    if trunc > 0 {
        parts.push(format!(
            "{trunc} cell(s) truncated at {max} chars; full: --json, or --max-chars 0"
        ));
    }
    parts.push(match info.next_page {
        Some(np) => format!("next: {}", next_cmd(p, np, info.next_size)),
        None => "end of results".to_string(),
    });
    format!("# {}: {}\n", p.name, parts.join("; "))
}

fn next_cmd(p: &RequestPlan, next_page: u32, next_size: Option<u32>) -> String {
    if p.kind == Kind::Raw {
        let mut s = format!("h1ro raw {}", p.path);
        // carry over every query pair of the requested URL, replacing page[number]
        let mut pairs = link_pairs(p.req.url());
        pairs.retain(|(k, _)| k != "page[number]");
        pairs.push(("page[number]".into(), next_page.to_string()));
        for (k, v) in pairs {
            s.push(' ');
            s.push_str(&shell_quote(&format!("{k}={v}")));
        }
        return s;
    }
    let mut s = format!("h1ro {}", p.label);
    if p.opts.bounty_only {
        s.push_str(" --bounty-only");
    }
    if let Some(f) = &p.opts.fields {
        s.push_str(&format!(" --fields {}", f.join(",")));
    }
    if let Some(m) = p.opts.max_chars {
        s.push_str(&format!(" --max-chars {m}"));
    }
    if let Some(q) = &p.opts.query {
        s.push_str(" --query ");
        s.push_str(&shell_quote(q));
    }
    if let Some(sort) = &p.opts.sort {
        s.push_str(" --sort ");
        s.push_str(&shell_quote(sort));
    }
    if let Some(n) = p.opts.since_id {
        s.push_str(&format!(" --since-id {n}"));
    }
    if let Some(t) = &p.opts.created_after {
        s.push_str(" --created-after ");
        s.push_str(&shell_quote(t));
    }
    if let Some(t) = &p.opts.updated_after {
        s.push_str(" --updated-after ");
        s.push_str(&shell_quote(t));
    }
    if p.opts.json {
        s.push_str(" --json");
    }
    if let Some(n) = next_size {
        s.push_str(&format!(" --limit {n}"));
    }
    s.push_str(&format!(" --page {next_page}"));
    s
}

fn fmt_err(e: &Refused) -> String {
    if e.0.starts_with("refused:") || e.0.starts_with("error:") {
        format!("{}\n", e.0)
    } else {
        format!("error: {}\n", e.0)
    }
}

/// Run one subcommand invocation. Returns the exit code; stdout/stderr text accumulate in `out`/`err`.
pub fn execute(
    args: &[String],
    creds: &Result<Credentials, Refused>,
    shown_user: &str,
    transport: &dyn Transport,
    out: &mut String,
    err: &mut String,
) -> i32 {
    let code = (|| -> i32 {
        let p = match plan(args) {
            Ok(Plan::Text(t)) => {
                out.push_str(&t);
                return 0;
            }
            Ok(Plan::Request(p)) => p,
            Err(e) => {
                err.push_str(&fmt_err(&e));
                return 1;
            }
        };
        if p.opts.dry_run {
            out.push_str(&dry_run_text(&p.req, shown_user, creds.is_ok()));
            return 0;
        }
        let creds = match creds {
            Ok(c) => c,
            Err(e) => {
                err.push_str(&fmt_err(e));
                return 1;
            }
        };
        let text = match perform(transport, &p.req, creds) {
            Ok(Outcome::Success(t)) => t,
            Ok(Outcome::HttpError(m)) => {
                err.push_str(&format!("error: {m}\n"));
                if p.kind == Kind::Me {
                    err.push_str("# note: /v1/hackers/me may 401 for Hacker API tokens; try `h1ro programs list --limit 1`\n");
                }
                return 1;
            }
            Err(e) => {
                err.push_str(&fmt_err(&Refused(creds.scrub(&e.0))));
                return 1;
            }
        };
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                err.push_str("error: response was not parseable JSON\n");
                return 1;
            }
        };
        render(&p, &v, &text, out, err)
    })();
    // Covers dry-run URLs and refusal text, not only response bodies.
    if let Ok(c) = creds {
        *out = c.scrub(out);
        *err = c.scrub(err);
    }
    code
}

fn records_of(v: &Value) -> Vec<&Value> {
    match v.get("data") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(o @ Value::Object(_)) => vec![o],
        _ => vec![],
    }
}

fn render(p: &RequestPlan, v: &Value, pretty: &str, out: &mut String, err: &mut String) -> i32 {
    let list = is_list(p.kind);
    // Raw is always pretty JSON; --json is pretty JSON for everyone.
    if p.opts.json || p.kind == Kind::Raw {
        out.push_str(pretty);
        out.push('\n');
        if p.opts.json && p.opts.bounty_only {
            err.push_str("# --bounty-only ignored with --json (full unfiltered JSON)\n");
        }
        if list || p.kind == Kind::Raw {
            if let Some(Value::Array(a)) = v.get("data") {
                let max = p.opts.max_chars.unwrap_or(80);
                err.push_str(&list_footer(p, v, a.len(), None, 0, max));
            }
        }
        return 0;
    }
    if list {
        let mut recs = records_of(v);
        let total = recs.len();
        let mut kept = None;
        if p.kind == Kind::ProgramsList && p.opts.bounty_only {
            recs.retain(|r| field(r, "offers_bounties").and_then(|b| b.as_bool()) == Some(true));
            kept = Some(recs.len());
        }
        let max = p.opts.max_chars.unwrap_or(80);
        let all = available_fields(&records_of(v));
        let cols: Vec<String> = match &p.opts.fields {
            Some(f) => {
                if !all.is_empty() {
                    if let Some(bad) = f.iter().find(|x| !all.contains(x)) {
                        err.push_str(&format!(
                            "error: unknown field '{bad}' (available: {})\n",
                            all.join(",")
                        ));
                        return 1;
                    }
                }
                f.clone()
            }
            None => match default_columns(p.kind) {
                Some(c) => c.iter().map(|s| s.to_string()).collect(),
                None => auto_columns(&records_of(v)),
            },
        };
        let (text, trunc) = table(&recs, &cols, max);
        out.push_str(&text);
        err.push_str(&list_footer(p, v, total, kept, trunc, max));
        return 0;
    }
    // single object
    let max = p.opts.max_chars.unwrap_or(200);
    let obj = match v.get("data") {
        Some(o @ Value::Object(_)) => o,
        _ => v,
    };
    let (text, mut trunc, mut omitted) = kv(obj, max);
    let mut activities = String::new();
    let mut activity_count = None;
    if p.kind == Kind::ReportsGet {
        if let Some((table, ntrunc, n)) = activities_table(obj, max) {
            trunc += ntrunc;
            activity_count = Some(n);
            activities = table;
            omitted.retain(|name| name != "activities");
        }
    }
    if text.is_empty() && activities.is_empty() {
        out.push_str(pretty);
        out.push('\n');
        return 0;
    }
    out.push_str(&text);
    if !activities.is_empty() {
        if !text.is_empty() {
            out.push('\n');
        }
        out.push_str(&activities);
    }
    let mut notes: Vec<String> = Vec::new();
    if trunc > 0 {
        notes.push(format!("{trunc} value(s) truncated at {max} chars (--max-chars 0 or --json for full)"));
    }
    if let Some(n) = activity_count {
        notes.push(format!("activities: {n} (attachment files are not downloaded)"));
    }
    if !omitted.is_empty() {
        notes.push(format!("relationships omitted: {} (--json for full)", omitted.join(",")));
    }
    if !notes.is_empty() {
        err.push_str(&format!("# {}: {}\n", p.label, notes.join("; ")));
    }
    0
}
