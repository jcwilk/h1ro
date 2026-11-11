//! h1ro: read-only HackerOne Hacker API wrapper (library part).
//!
//! Everything that decides *whether* a request may be made lives here and is
//! pure (no network). The only code that touches the network is `http.rs`,
//! and it can only be reached through a [`ValidatedRequest`], which can only
//! be built by [`validate_path`] + [`validate_params`] + [`build_request`].

pub mod cmd;
pub mod http;
pub mod render;

use regex::Regex;
use std::fmt;

pub const HOST: &str = "https://api.hackerone.com";
pub const HOST_NAME: &str = "api.hackerone.com";
pub const PATH_PREFIX: &str = "/v1/hackers";
pub const DEFAULT_USERNAME: &str = "jcwilk";
pub const MAX_ERROR_CHARS: usize = 2000;
const MAX_PATH_LEN: usize = 1024;
const MAX_QUERY_PARAMS: usize = 16;
const MAX_PARAM_VALUE_CHARS: usize = 2048;
const MAX_URL_LEN: usize = 8192;

/// Words that, if they equal or prefix an alphanumeric token of a path segment
/// or a query-parameter NAME, cause a local refusal. `invitation`,
/// `submission`, `rotation` are listed because they do not prefix-match the
/// shorter roots.
pub const DENY_WORDS: [&str; 15] = [
    "accept",
    "decline",
    "invite",
    "invitation",
    "join",
    "token",
    "rotate",
    "rotation",
    "delete",
    "archive",
    "close",
    "submit",
    "submission",
    "mark",
    "export",
];

/// Full-path regexes that are always refused (checked before the word list).
/// `submit` is the documented POST. A single attachment id is the documented DELETE;
/// the collection GET (`.../attachments` with nothing after it) stays allowed.
/// `/v1/hackers/reports` with no id is the create-report POST; the read is
/// `/v1/hackers/reports/{id}`.
pub const EXPLICIT_DENY: [&str; 3] = [
    r"^/v1/hackers/report_intents/[^/]+/submit$",
    r"^/v1/hackers/report_intents/[^/]+/attachments/.+",
    r"^/v1/hackers/reports$",
];

pub const JSON_TYPES: [&str; 3] = ["application/json", "application/vnd.api+json", "text/json"];

/// A local refusal (or surfaced HTTP error). The message never contains the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Refused {}

fn refuse<T>(msg: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(msg.into()))
}

/// Keep refusal text on one line and bounded, so a huge argument cannot flood a log.
fn clip(s: &str) -> String {
    let mut chars = s.chars();
    let head: String = chars.by_ref().take(80).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// Lowercase alphanumeric tokens of `text` (split on every non [a-z0-9] char).
pub fn tokens(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Equal-or-prefix match, so `tokens`, `invitations`, `submissions`, `mark-read`
/// match but a handle like `remarkable` / `bookmark` does not match `mark`.
pub fn word_denied(text: &str) -> Option<&'static str> {
    for tok in tokens(text) {
        for word in DENY_WORDS {
            if tok == word || tok.starts_with(word) {
                return Some(word);
            }
        }
    }
    None
}

fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '~' | '-')
}

/// Validate a bare API path. Returns it unchanged if acceptable.
pub fn validate_path(raw: &str) -> Result<String, Refused> {
    if raw.len() > MAX_PATH_LEN {
        return refuse("refused: path is too long");
    }
    let shown = clip(raw);
    if raw.is_empty() || raw.starts_with('-') {
        return refuse("refused: path required");
    }
    if raw.chars().any(|c| c.is_control()) {
        return refuse("refused: path contains control characters");
    }
    if raw.chars().any(|c| c.is_whitespace()) {
        return refuse("refused: path contains whitespace");
    }
    if !raw.is_ascii() {
        return refuse("refused: path contains non-ASCII characters");
    }
    if raw.contains('%') {
        return refuse(format!(
            "refused: percent-encoding is not allowed in paths: {shown}"
        ));
    }
    for bad in ["://", "\\", "?", "#", "@"] {
        if raw.contains(bad) {
            return refuse(format!(
                "refused: path must be a bare API path, not a URL: {shown}"
            ));
        }
    }
    let parts: Vec<&str> = raw.split('/').collect();
    if !raw.starts_with('/')
        || parts.iter().any(|p| *p == "." || *p == "..")
        || parts[1..].iter().any(|p| p.is_empty())
    {
        return refuse(format!(
            "refused: path is not a normalized /v1/hackers/... path: {shown}"
        ));
    }
    // Prefix lock: exactly /v1/hackers or /v1/hackers/<segments>, ASCII-only segments.
    let rest = match raw.strip_prefix(PATH_PREFIX) {
        Some(r) => r,
        None => {
            return refuse(format!(
                "refused: only paths under /v1/hackers on api.hackerone.com are allowed: {shown}"
            ))
        }
    };
    let rest_ok = rest.is_empty()
        || (rest.starts_with('/') && rest[1..].split('/').all(|s| !s.is_empty() && s.chars().all(is_path_char)));
    if !rest_ok {
        return refuse(format!(
            "refused: only paths under /v1/hackers on api.hackerone.com are allowed: {shown}"
        ));
    }
    for rx in EXPLICIT_DENY {
        // Patterns are compile-time constants; a failure here is a programming error.
        let re = Regex::new(rx).expect("EXPLICIT_DENY pattern must compile");
        if re.is_match(raw) {
            return refuse(format!("refused: path is denylisted: {shown}"));
        }
    }
    for seg in &parts {
        if seg.is_empty() {
            continue;
        }
        if let Some(word) = word_denied(seg) {
            return refuse(format!(
                "refused: path segment '{seg}' contains denylisted word '{word}'"
            ));
        }
    }
    Ok(raw.to_string())
}

/// Parameter NAME shape: `name` or `name[sub]` or `name[sub__op]` (JSON:API style).
pub fn param_name_ok(name: &str) -> bool {
    fn ident(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
    let (base, bracket) = match name.find('[') {
        Some(i) => (&name[..i], Some(&name[i..])),
        None => (name, None),
    };
    let mut chars = base.chars();
    let first_ok = chars.next().map_or(false, |c| c.is_ascii_alphabetic());
    if !first_ok || !ident(base) {
        return false;
    }
    match bracket {
        None => true,
        Some(b) => {
            if !(b.starts_with('[') && b.ends_with(']') && b.len() >= 3) {
                return false;
            }
            let inner = &b[1..b.len() - 1];
            match inner.split_once("__") {
                Some((a, c)) => ident(a) && ident(c),
                None => ident(inner),
            }
        }
    }
}

/// One query parameter. Names are shape-checked and denylist-checked.
/// Values are ASCII, may contain spaces, and may not contain other whitespace or controls.
fn validate_pair(key: &str, value: &str) -> Result<(), Refused> {
    if !param_name_ok(key) {
        return refuse(format!("refused: param name not allowed: {}", clip(key)));
    }
    if let Some(word) = word_denied(key) {
        return refuse(format!(
            "refused: param '{key}' contains denylisted word '{word}'"
        ));
    }
    if value.chars().count() > MAX_PARAM_VALUE_CHARS {
        return refuse(format!("refused: param '{key}' value is too long"));
    }
    let value_ok = value.chars().all(|c| {
        c.is_ascii() && !c.is_ascii_control() && (c == ' ' || !c.is_ascii_whitespace())
    });
    if !value_ok {
        return refuse(format!(
            "refused: param '{key}' value must be ASCII without control characters"
        ));
    }
    Ok(())
}

/// Validate `key=value` pairs. Names are shape-checked and denylist-checked.
/// Duplicate names are refused (stricter than the Python version).
pub fn validate_params(pairs: &[String]) -> Result<Vec<(String, String)>, Refused> {
    if pairs.len() > MAX_QUERY_PARAMS {
        return refuse(format!("refused: too many query parameters (max {MAX_QUERY_PARAMS})"));
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for kv in pairs {
        if kv.len() > MAX_PATH_LEN + MAX_PARAM_VALUE_CHARS {
            return refuse("refused: param is too long");
        }
        let (key, value) = match kv.split_once('=') {
            Some(p) => p,
            None => return refuse(format!("refused: param must be key=value: {}", clip(kv))),
        };
        validate_pair(key, value)?;
        if out.iter().any(|(k, _)| k == key) {
            return refuse(format!("refused: duplicate param: {key}"));
        }
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

/// Strict percent-encoding: only RFC 3986 unreserved characters pass through.
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A request that has passed every check. Fields are private: the only way to
/// get one is [`build_request`]. There is deliberately no method field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRequest {
    url: String,
}

impl ValidatedRequest {
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// True only for `https://api.hackerone.com/v1/hackers` with an optional further
/// path or query. A bare prefix is not enough: `api.hackerone.com.evil` fails,
/// and `.` / `..` / empty / percent-encoded path segments fail.
pub fn url_locked(url: &str) -> bool {
    if url.len() > MAX_URL_LEN || !url.is_ascii() {
        return false;
    }
    if url.bytes().any(|b| b.is_ascii_whitespace() || matches!(b, b'@' | b'\\' | b'#')) {
        return false;
    }
    let Some(rest) = url.strip_prefix(HOST) else {
        return false;
    };
    let Some(after) = rest.strip_prefix(PATH_PREFIX) else {
        return false;
    };
    let (path, query) = match after.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (after, None),
    };
    if let Some(q) = query {
        if q.is_empty() || q.bytes().any(|b| matches!(b, b'?' | b'#' | b'@' | b'\\')) {
            return false;
        }
    }
    if path.is_empty() {
        return true;
    }
    if !path.starts_with('/') {
        return false;
    }
    path.split('/').skip(1).all(|seg| {
        !seg.is_empty()
            && seg != "."
            && seg != ".."
            && !seg.contains('%')
            && seg.chars().all(is_path_char)
    })
}

pub fn build_request(path: &str, params: &[(String, String)]) -> Result<ValidatedRequest, Refused> {
    // Re-validate defensively: a ValidatedRequest is always built from clean inputs.
    let path = validate_path(path)?;
    if params.len() > MAX_QUERY_PARAMS {
        return refuse(format!("refused: too many query parameters (max {MAX_QUERY_PARAMS})"));
    }
    let mut seen: Vec<&str> = Vec::new();
    for (k, v) in params {
        validate_pair(k, v)?;
        if seen.iter().any(|e| *e == k.as_str()) {
            return refuse(format!("refused: duplicate param: {k}"));
        }
        seen.push(k);
    }
    let mut url = format!("{HOST}{path}");
    if !params.is_empty() {
        let qs: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }
    if !url_locked(&url) {
        return refuse("refused: URL is outside https://api.hackerone.com/v1/hackers");
    }
    Ok(ValidatedRequest { url })
}

/// Credentials from the environment only. `Debug` is deliberately redacted.
#[derive(Clone)]
pub struct Credentials {
    username: String,
    token: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    pub fn new(username: &str, token: &str) -> Result<Self, Refused> {
        if token.is_empty() {
            return refuse("H1_API_TOKEN not set");
        }
        let user_ok = (1..=64).contains(&username.len())
            && !username.contains(':')
            && username
                .bytes()
                .all(|b| b.is_ascii() && !b.is_ascii_control() && !b.is_ascii_whitespace());
        if !user_ok {
            return refuse("refused: H1_API_USERNAME is invalid");
        }
        // Printable ASCII. Space is allowed (Basic passwords may contain it); CR/LF and
        // other controls are not, so the Authorization header stays one line.
        let token_ok = token.len() <= 1024
            && token.bytes().all(|b| b.is_ascii() && !b.is_ascii_control());
        if !token_ok {
            return refuse("refused: H1_API_TOKEN must be ASCII without control characters");
        }
        Ok(Self {
            username: username.to_string(),
            token: token.to_string(),
        })
    }

    /// Read H1_API_TOKEN (required) and H1_API_USERNAME (default jcwilk).
    pub fn from_env() -> Result<Self, Refused> {
        let token = std::env::var("H1_API_TOKEN").unwrap_or_default();
        let user = std::env::var("H1_API_USERNAME").unwrap_or_else(|_| DEFAULT_USERNAME.to_string());
        Self::new(&user, &token)
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn basic_header(&self) -> String {
        use base64::Engine;
        let raw = format!("{}:{}", self.username, self.token);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    /// Remove the token (and its base64 Basic form) from any text before display.
    pub fn scrub(&self, text: &str) -> String {
        scrub_secrets(&self.username, &self.token, text)
    }
}

/// Remove `token`, its percent-encoding, and the Basic-auth base64 blobs from `text`.
/// Encoded forms are only substituted when the token is at least 8 characters, so a
/// short secret cannot blank out ordinary `%XX` sequences.
pub fn scrub_secrets(username: &str, token: &str, text: &str) -> String {
    use base64::Engine;
    if token.is_empty() {
        return text.to_string();
    }
    let mut t = text.to_string();
    if (1..=64).contains(&username.len()) && !username.contains(':') && username.is_ascii() {
        let raw = format!("{username}:{token}");
        let enc = base64::engine::general_purpose::STANDARD.encode(raw);
        t = t.replace(&enc, "<redacted>");
    }
    if token.len() >= 8 {
        let bare = base64::engine::general_purpose::STANDARD.encode(token.as_bytes());
        t = t.replace(&bare, "<redacted>");
        let pct = urlencode(token);
        if pct != token {
            t = t.replace(&pct, "<redacted>");
            t = t.replace(&pct.to_ascii_lowercase(), "<redacted>");
        }
    }
    t.replace(token, "<redacted>")
}

/// What a transport hands back. No verb, no body-to-send anywhere.
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// The ONLY network capability the rest of the program has: a GET.
pub trait Transport {
    fn get(&self, request: &ValidatedRequest, auth_header: &str) -> Result<RawResponse, Refused>;
}

fn media_type(ct: Option<&str>) -> String {
    let raw = ct.unwrap_or("");
    let ctype = raw
        .split(|c: char| c == ';' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ctype.is_empty() {
        return String::new();
    }
    if ctype.len() > 80
        || !ctype
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '+' | '-' | '.'))
    {
        return "invalid".into();
    }
    ctype
}

/// Return pretty-printed JSON, or refuse if the body/Content-Type is not JSON.
pub fn require_json(status: u16, content_type: Option<&str>, body: &[u8]) -> Result<String, Refused> {
    let text = String::from_utf8_lossy(body);
    let ctype = media_type(content_type);
    let shown = if ctype.is_empty() { "missing" } else { ctype.as_str() };
    let msg = || format!("refused: response is not JSON (HTTP {status}, content-type: {shown})");
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return refuse(msg()),
    };
    let type_ok = ctype.contains('/')
        && JSON_TYPES
            .iter()
            .any(|t| ctype == *t || ctype.ends_with("+json"));
    if !type_ok {
        return refuse(msg());
    }
    Ok(serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_string()))
}

/// Outcome of a performed request.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 2xx JSON, pretty-printed.
    Success(String),
    /// 4xx/5xx with JSON body; surfaced once, never retried: "HTTP N: <raw, truncated>".
    HttpError(String),
}

/// Send one GET through `transport` and classify the response. Exactly one call; no retry.
pub fn perform(
    transport: &dyn Transport,
    req: &ValidatedRequest,
    creds: &Credentials,
) -> Result<Outcome, Refused> {
    let resp = transport.get(req, &creds.basic_header())?;
    let status = resp.status;
    if (300..400).contains(&status) {
        return refuse(format!("refused: redirect (HTTP {status}) not followed"));
    }
    if status >= 400 {
        // Validate JSON-ness but surface the raw text (truncated), like the Python tool.
        if require_json(status, resp.content_type.as_deref(), &resp.body).is_err() {
            return refuse(format!("HTTP {status}: refused: response is not JSON"));
        }
        let raw = String::from_utf8_lossy(&resp.body);
        let clipped: String = raw.chars().take(MAX_ERROR_CHARS).collect();
        return Ok(Outcome::HttpError(format!("HTTP {status}: {}", creds.scrub(&clipped))));
    }
    if !(200..300).contains(&status) {
        return refuse(format!("refused: unexpected HTTP status {status}"));
    }
    let out = require_json(status, resp.content_type.as_deref(), &resp.body)?;
    Ok(Outcome::Success(creds.scrub(&out)))
}

/// Legacy raw-path-mode help text (kept; the overview in `cmd::OVERVIEW` is what `--help` prints now).
pub const USAGE: &str = "\
h1ro - read-only HackerOne Hacker API wrapper (GET only)

Usage:
  h1ro [--dry-run] <path> [key=value ...]
  h1ro --help

Examples:
  h1ro /v1/hackers/me/programs page[size]=100
  h1ro /v1/hackers/programs/acme/structured_scopes page[size]=100
  h1ro /v1/hackers/reports/12345
  h1ro --dry-run /v1/hackers/programs page[size]=1

Env:
  H1_API_TOKEN     API token (required; never accepted on the command line)
  H1_API_USERNAME  API username (default: jcwilk)

Only GET requests to https://api.hackerone.com/v1/hackers/... are possible.
No redirects are followed, no retries are made, and non-JSON responses are refused.
--dry-run validates and prints the URL it WOULD GET without any network call.
";

/// Parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Cli {
    Help,
    NoArgs,
    Run {
        dry_run: bool,
        path: String,
        params: Vec<String>,
    },
}

/// Parse args (excluding argv[0]). Only `--dry-run` and `-h/--help` are flags;
/// any other dash-leading argument is refused. There is no verb/body/header/host flag.
pub fn parse_args(args: &[String]) -> Result<Cli, Refused> {
    if args.is_empty() {
        return Ok(Cli::NoArgs);
    }
    let mut dry_run = false;
    let mut positional: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => return Ok(Cli::Help),
            "--dry-run" => dry_run = true,
            s if s.starts_with('-') => {
                return refuse(format!("refused: unknown option: {s}"));
            }
            _ => positional.push(a.clone()),
        }
    }
    if positional.is_empty() {
        return refuse("refused: path required");
    }
    let path = positional.remove(0);
    Ok(Cli::Run {
        dry_run,
        path,
        params: positional,
    })
}

/// Text printed by `--dry-run`. Contains the URL and username, never the token.
pub fn dry_run_text(req: &ValidatedRequest, username: &str, token_present: bool) -> String {
    format!(
        "DRY RUN: no network call made.\nWould GET {}\nAuth: HTTP Basic (username={}, token from H1_API_TOKEN: {})\n",
        req.url(),
        username,
        if token_present { "present" } else { "NOT SET" }
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cmd_tests;
