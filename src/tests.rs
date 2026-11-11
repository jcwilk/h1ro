use super::*;
use std::cell::RefCell;

const TOKEN: &str = "SECRET-TOKEN-abc123XYZ";
const USER: &str = "tester";

fn s(x: &str) -> String {
    x.to_string()
}
fn creds() -> Credentials {
    Credentials::new(USER, TOKEN).unwrap()
}

struct Fake {
    calls: RefCell<Vec<(String, String)>>,
    resp: RefCell<Option<Result<RawResponse, Refused>>>,
}
impl Fake {
    fn new(status: u16, ct: Option<&str>, body: &str) -> Self {
        Fake {
            calls: RefCell::new(vec![]),
            resp: RefCell::new(Some(Ok(RawResponse {
                status,
                content_type: ct.map(s),
                body: body.as_bytes().to_vec(),
            }))),
        }
    }
}
impl Transport for Fake {
    fn get(&self, r: &ValidatedRequest, auth: &str) -> Result<RawResponse, Refused> {
        self.calls.borrow_mut().push((r.url().to_string(), auth.to_string()));
        self.resp.borrow_mut().take().expect("second call: retry detected")
    }
}
fn req(path: &str) -> ValidatedRequest {
    build_request(path, &[]).unwrap()
}

// ---------- path: allowed ----------
#[test]
fn allows_documented_paths() {
    for p in [
        "/v1/hackers",
        "/v1/hackers/programs",
        "/v1/hackers/me/programs",
        "/v1/hackers/me/reports",
        "/v1/hackers/reports/12345",
        "/v1/hackers/programs/acme/structured_scopes",
        "/v1/hackers/programs/acme/weaknesses",
        "/v1/hackers/payments/balance",
        "/v1/hackers/hacktivity",
        "/v1/hackers/report_intents",
        "/v1/hackers/report_intents/25/attachments",
    ] {
        assert_eq!(validate_path(p).unwrap(), p, "{p}");
    }
}

#[test]
fn ordinary_handles_allowed_including_remarkable_and_bookmark() {
    for p in [
        "/v1/hackers/programs/gitlab",
        "/v1/hackers/programs/security",
        "/v1/hackers/programs/remarkable",
        "/v1/hackers/programs/bookmark",
    ] {
        assert_eq!(validate_path(p).unwrap(), p);
    }
}

// ---------- path: host/prefix lock ----------
#[test]
fn rejects_paths_outside_v1_hackers() {
    for p in [
        "/v1/programs/acme",
        "/v1/me",
        "/v1/hackersX",
        "/v1/hackersx/programs",
        "/v2/hackers/programs",
        "/v1/hacker/programs",
        "/",
        "v1/hackers/programs",
        "/V1/hackers/programs",
        "/v1/customer/hackers",
        "/x/v1/hackers/programs",
    ] {
        assert!(validate_path(p).is_err(), "{p}");
    }
}

#[test]
fn rejects_bad_empty_and_dash_paths() {
    for p in ["", "-x", "--dry-run", "/v1/hackers/", "/v1/hackers//me", "/v1/hackers/me/"] {
        assert!(validate_path(p).is_err(), "{p:?}");
    }
}

#[test]
fn rejects_urls_in_path() {
    for p in [
        "https://api.hackerone.com/v1/hackers/me/programs",
        "http://evil.example/v1/hackers/programs",
        "//evil.example/v1/hackers/programs",
        "/v1/hackers/me/programs?page[size]=100",
        "/v1/hackers/me/programs#x",
        "/v1/hackers@evil.example/programs",
        "/v1/hackers/x://y",
    ] {
        let e = validate_path(p).unwrap_err();
        assert!(e.0.starts_with("refused"), "{p}");
    }
    assert!(validate_path("https://api.hackerone.com/v1/hackers/x").unwrap_err().0.contains("not a URL"));
}

#[test]
fn rejects_encoded_traversal_backslash_ctrl_whitespace() {
    for p in [
        "/v1/hackers/%2e%2e/reports",
        "/v1/hackers/me%2fprograms",
        "/v1/hackers/me%3Fx",
        "/v1/hackers/programs/acme%20x",
        "/v1/hackers/%",
        "/v1/hackers/../programs",
        "/v1/hackers/me/./programs",
        "/v1/hackers/me/..",
        "/v1/hackers\\programs",
        "/v1/hackers/me\\..\\programs",
        "/v1/hackers/me\n/programs",
        "/v1/hackers/me\r\nX: y",
        "/v1/hackers/me\0",
        "/v1/hackers/me\t",
        "/v1/hackers/me programs",
        "/v1/hackers/me\u{a0}programs",
        "/v1/hackers/programs/caf\u{e9}",
        "/v1/hackers/programs/\u{ff0f}x",
    ] {
        assert!(validate_path(p).is_err(), "{p:?}");
    }
}

// ---------- path: denylist ----------
#[test]
fn every_deny_word_is_refused_as_segment() {
    for w in DENY_WORDS {
        let p = format!("/v1/hackers/programs/acme/{w}");
        let e = validate_path(&p).unwrap_err();
        assert!(e.0.contains("refused") && e.0.contains(w), "{p}: {e}");
        // prefix form
        let p2 = format!("/v1/hackers/me/{w}s");
        assert!(validate_path(&p2).is_err(), "{p2}");
        // uppercase
        let p3 = format!("/v1/hackers/me/{}", w.to_uppercase());
        assert!(validate_path(&p3).is_err(), "{p3}");
    }
}

#[test]
fn segment_denylist_cases_match_python() {
    for (p, w) in [
        ("/v1/hackers/invitations", "invitation"),
        ("/v1/hackers/programs/acme/invite", "invite"),
        ("/v1/hackers/me/accept", "accept"),
        ("/v1/hackers/me/decline", "decline"),
        ("/v1/hackers/me/join", "join"),
        ("/v1/hackers/tokens", "token"),
        ("/v1/hackers/me/token/rotate", "token"),
        ("/v1/hackers/api-tokens", "token"),
        ("/v1/hackers/reports/1/delete", "delete"),
        ("/v1/hackers/reports/1/archive", "archive"),
        ("/v1/hackers/reports/1/close", "close"),
        ("/v1/hackers/report_intents/25/submit", "submit"),
        ("/v1/hackers/reports/1/mark_read", "mark"),
        ("/v1/hackers/reports/1/mark-read", "mark"),
        ("/v1/hackers/me/export", "export"),
        ("/v1/hackers/submissions", "submission"),
        ("/v1/hackers/me/rotation", "rotation"),
        ("/v1/hackers/me/rotate", "rotate"),
    ] {
        let e = validate_path(p).unwrap_err();
        assert!(e.0.contains(w), "{p}: {e}");
        assert!(e.0.contains("refused"));
    }
}

#[test]
fn explicit_deny_submit_path_is_refused_as_denylisted() {
    let e = validate_path("/v1/hackers/report_intents/25/submit").unwrap_err();
    assert!(e.0.contains("path is denylisted"), "{e}");
    assert!(validate_path("/v1/hackers/report_intents/abc-1/submit").is_err());
    // regex is anchored at both ends
    let re = regex::Regex::new(EXPLICIT_DENY[0]).unwrap();
    assert!(re.is_match("/v1/hackers/report_intents/1/submit"));
    assert!(!re.is_match("/v1/hackers/report_intents/1/submit/x"));
    assert!(!re.is_match("/v1/hackers/report_intents//submit"));
    // collection GET stays allowed; the extra id is the DELETE url
    assert!(validate_path("/v1/hackers/report_intents/25/attachments").is_ok());
    let gone = validate_path("/v1/hackers/report_intents/25/attachments/9").unwrap_err();
    assert!(gone.0.contains("path is denylisted"), "{gone}");
    assert!(validate_path("/v1/hackers/report_intents/25/attachments/9/x").is_err());
    // the bare collection is the create-report POST; a report id remains a read
    assert!(validate_path("/v1/hackers/reports").unwrap_err().0.contains("denylisted"));
    assert!(validate_path("/v1/hackers/reports/1").is_ok());
}

#[test]
fn deny_list_contents_are_exactly_the_documented_set() {
    assert_eq!(
        DENY_WORDS.to_vec(),
        vec![
            "accept", "decline", "invite", "invitation", "join", "token", "rotate", "rotation",
            "delete", "archive", "close", "submit", "submission", "mark", "export"
        ]
    );
    assert_eq!(
        EXPLICIT_DENY.to_vec(),
        vec![
            r"^/v1/hackers/report_intents/[^/]+/submit$",
            r"^/v1/hackers/report_intents/[^/]+/attachments/.+",
            r"^/v1/hackers/reports$",
        ]
    );
}

#[test]
fn tokenizer_and_prefix_logic() {
    assert_eq!(tokens("Mark_Read-2x"), vec!["mark", "read", "2x"]);
    assert_eq!(word_denied("remarkable"), None);
    assert_eq!(word_denied("bookmark"), None);
    assert_eq!(word_denied("marked"), Some("mark"));
    assert_eq!(word_denied("structured_scopes"), None);
    assert_eq!(word_denied("report_intents"), None);
}

// ---------- params ----------
fn v(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| s(x)).collect()
}

#[test]
fn allows_documented_params() {
    let p = validate_params(&v(&[
        "page[size]=100",
        "page[number]=2",
        "queryString=severity_rating:critical",
        "sort=-disclosed_at",
        "filter[id__gt]=10",
        "filter[created_at__gt]=2024-01-01T00:00:00Z",
    ]))
    .unwrap();
    assert_eq!(p[0], (s("page[size]"), s("100")));
    assert_eq!(p[3], (s("sort"), s("-disclosed_at")));
    assert_eq!(p.len(), 6);
}

#[test]
fn rejects_bad_and_denylisted_param_names() {
    for kv in [
        "bad name=1",
        "page[size=1",
        "page]size[=1",
        ";rm=1",
        "export=1",
        "token=abc",
        "mark[read]=1",
        "filter[token]=1",
        "invite=1",
        "accept=1",
        "=1",
        "1abc=1",
        "page[]=1",
        "page[a][b]=1",
        "page[a__]=1",
        "page[__a]=1",
        "a/b=1",
        "a%20b=1",
        "-x=1",
        "--method=POST",
        "method=POST", // allowed shape; checked separately below
    ] {
        let r = validate_params(&v(&[kv]));
        if kv == "method=POST" {
            // a plain, harmless read-filter name; it is only a query string and cannot change the verb
            assert!(r.is_ok());
        } else {
            assert!(r.is_err(), "{kv}");
        }
    }
}

#[test]
fn rejects_missing_equals_and_duplicates() {
    assert!(validate_params(&v(&["pagesize"])).is_err());
    assert!(validate_params(&v(&["page[size]=1", "page[size]=2"])).is_err());
}

#[test]
fn param_values_are_percent_encoded_and_cannot_inject() {
    assert!(validate_params(&v(&["queryString=a\r\nb"])).is_err());
    let p = validate_params(&v(&["queryString=a b&x=1#frag/../?"])).unwrap();
    let r = build_request("/v1/hackers/programs", &p).unwrap();
    let url = r.url();
    assert!(url.starts_with("https://api.hackerone.com/v1/hackers/programs?queryString="));
    let q = url.split_once('?').unwrap().1;
    assert!(!q.contains(['&', '#', ' ', '/', '?']), "{q}");
    assert_eq!(url.matches('?').count(), 1);
}

#[test]
fn brackets_in_names_are_encoded() {
    let p = validate_params(&v(&["page[size]=1", "page[number]=2"])).unwrap();
    let r = build_request("/v1/hackers/programs", &p).unwrap();
    assert_eq!(
        r.url(),
        "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1&page%5Bnumber%5D=2"
    );
}

// ---------- request construction / GET-only / host lock ----------
#[test]
fn build_request_rechecks_params_and_refuses_a_lookalike_host() {
    assert!(build_request("/v1/hackers/programs", &[(s("token"), s("x"))]).is_err());
    assert!(build_request("/v1/hackers/programs", &[(s("q"), s("a\nb"))]).is_err());
    assert!(build_request("/v1/hackers/programs", &[(s("q"), "café".into())]).is_err());
    let long = format!("/v1/hackers/{}", "a".repeat(2000));
    let e = validate_path(&long).unwrap_err();
    assert!(e.0.contains("too long") && e.0.len() < 80, "{e}");
    for bad in [
        "https://api.hackerone.com.evil/v1/hackers",
        "https://api.hackerone.com/v1/hackers.evil",
        "http://api.hackerone.com/v1/hackers",
        "https://user:pw@api.hackerone.com/v1/hackers",
        "https://api.hackerone.com/v1/hackers/../programs",
        "https://api.hackerone.com/v1/hackers/%2e%2e",
    ] {
        assert!(!url_locked(bad), "{bad}");
    }
    assert!(url_locked("https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1"));
    let evil = ValidatedRequest { url: "https://api.hackerone.com.evil/v1/hackers".into() };
    let err = http::UreqTransport::new().get(&evil, "Basic eA==").unwrap_err();
    assert!(err.0.contains("host"), "{err}");
}

#[test]
fn request_url_is_locked_to_host_and_prefix() {
    let r = build_request("/v1/hackers/me/programs", &[]).unwrap();
    assert_eq!(r.url(), "https://api.hackerone.com/v1/hackers/me/programs");
    assert!(build_request("/v1/programs/x", &[]).is_err());
    assert!(build_request("https://evil.example/v1/hackers", &[]).is_err());
    assert!(build_request("/v1/hackers/tokens", &[]).is_err());
    assert_eq!(HOST, "https://api.hackerone.com");
}

#[test]
fn transport_trait_exposes_only_get() {
    // Compile-time/shape check: a Transport impl needs exactly `get`. The fake
    // implements only that, and ValidatedRequest has no method/body accessors.
    let f = Fake::new(200, Some("application/json"), "{}");
    let _ = perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap();
    assert_eq!(f.calls.borrow().len(), 1);
}

#[test]
fn http_module_uses_only_get_verb() {
    let src: String = include_str!("http.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let src = src.as_str();
    let verbs = ["post", "put", "patch", "delete", "head", "options", "request", "send", "trace", "connect"];
    for vb in verbs {
        for open in [".", "::"] {
            let needle = format!("{open}{vb}(");
            assert!(!src.contains(&needle), "http.rs contains forbidden call {needle}");
        }
    }
    let needle = [".", "get", "("].concat();
    assert_eq!(src.matches(&needle).count(), 1, "exactly one .get( call expected");
    for body in ["send_string", "send_json", "send_bytes", "send_form", "send_reader"] {
        assert!(!src.contains(body), "{body}");
    }
    assert!(src.contains("redirects(0)"));
    assert!(src.contains("https_only(true)"));
    assert!(!src.contains("proxy"), "no proxy configuration allowed");
}

#[test]
fn library_and_main_have_no_http_verb_selection() {
    let lib = include_str!("lib.rs");
    let main = include_str!("main.rs");
    for src in [lib, main] {
        for bad in ["ureq::", "reqwest", "hyper", "TcpStream", "std::process::Command", "Command::new"] {
            assert!(!src.contains(bad), "unexpected {bad}");
        }
    }
    // no env var is consulted other than the two credential variables
    let mut vars: Vec<&str> = vec![];
    for src in [lib, main] {
        for part in src.split("env::var(").skip(1) {
            let name = part.split(')').next().unwrap();
            vars.push(name);
        }
    }
    assert!(vars.iter().all(|n| *n == "\"H1_API_TOKEN\"" || *n == "\"H1_API_USERNAME\""), "{vars:?}");
}

// ---------- CLI parsing ----------
#[test]
fn cli_has_only_dry_run_and_help_flags() {
    assert_eq!(parse_args(&[]).unwrap(), Cli::NoArgs);
    assert_eq!(parse_args(&v(&["--help"])).unwrap(), Cli::Help);
    assert_eq!(parse_args(&v(&["-h"])).unwrap(), Cli::Help);
    for bad in [
        "-X", "--request", "--method=POST", "--data", "-d", "--url", "--host", "--token", "-H",
        "--follow", "--retry", "--output", "-L", "--dry-run=no",
    ] {
        assert!(parse_args(&v(&[bad, "/v1/hackers/programs"])).is_err(), "{bad}");
        assert!(parse_args(&v(&["/v1/hackers/programs", bad])).is_err(), "{bad}");
    }
    match parse_args(&v(&["--dry-run", "/v1/hackers/programs", "page[size]=1"])).unwrap() {
        Cli::Run { dry_run, path, params } => {
            assert!(dry_run);
            assert_eq!(path, "/v1/hackers/programs");
            assert_eq!(params, v(&["page[size]=1"]));
        }
        o => panic!("{o:?}"),
    }
    assert!(parse_args(&v(&["--dry-run"])).is_err());
}

// ---------- credentials / token never printed ----------
#[test]
fn credentials_validation_and_redacted_debug() {
    assert_eq!(Credentials::new(USER, "").unwrap_err().0, "H1_API_TOKEN not set");
    assert!(Credentials::new("a:b", TOKEN).is_err());
    assert!(Credentials::new("", TOKEN).is_err());
    assert!(Credentials::new("a b", TOKEN).is_err());
    assert!(Credentials::new("usér", TOKEN).is_err());
    assert!(Credentials::new(USER, "tok\nen").is_err());
    assert!(Credentials::new(USER, "tok\u{2028}en-secret").is_err());
    assert!(Credentials::new(USER, &"x".repeat(1025)).is_err());
    let dbg = format!("{:?}", creds());
    assert!(!dbg.contains(TOKEN));
    assert!(dbg.contains("redacted"));
}

#[test]
fn basic_header_is_correct() {
    // base64("tester:SECRET-TOKEN-abc123XYZ")
    use base64::Engine;
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{TOKEN}"))
    );
    assert_eq!(creds().basic_header(), want);
    // known vector
    assert_eq!(Credentials::new("Aladdin", "open sesame").unwrap().basic_header(), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
}

#[test]
fn dry_run_output_has_no_token_and_says_would_get() {
    let r = build_request("/v1/hackers/programs", &[(s("page[size]"), s("1"))]).unwrap();
    let t = dry_run_text(&r, creds().username(), true);
    assert!(!t.contains(TOKEN));
    assert!(!t.contains(&creds().basic_header()));
    assert!(t.contains("Would GET https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1"));
    assert!(t.contains("no network call made"));
}

#[test]
fn scrub_removes_token_and_basic_blob() {
    let c = creds();
    let text = format!("echo {TOKEN} and {}", c.basic_header());
    let out = c.scrub(&text);
    assert!(!out.contains(TOKEN));
    assert!(!out.contains(c.basic_header().strip_prefix("Basic ").unwrap()));
}

#[test]
fn scrub_removes_percent_encoded_token_and_its_lowercase_hex() {
    let c = Credentials::new(USER, "sec ret+1/2").unwrap();
    let enc = urlencode("sec ret+1/2");
    assert!(enc.contains("%20") && enc.contains("%2B") && enc.contains("%2F"));
    let out = c.scrub(&format!("{enc} {} sec ret+1/2", enc.to_ascii_lowercase()));
    assert!(!out.contains("sec ret"), "{out}");
    assert!(!out.contains("%20") && !out.contains("%2b") && !out.contains("%2B"), "{out}");
    assert!(out.contains("<redacted>"));
}

#[test]
fn refusal_messages_never_contain_token() {
    for p in ["/v1/hackers/tokens", "/v1/programs/x", "https://x/y"] {
        let e = validate_path(p).unwrap_err();
        assert!(!e.0.contains(TOKEN));
    }
}

#[test]
fn http_error_body_echoing_token_is_scrubbed() {
    let body = format!(r#"{{"errors":[{{"detail":"bad {TOKEN}"}}]}}"#);
    let f = Fake::new(401, Some("application/json"), &body);
    match perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap() {
        Outcome::HttpError(m) => assert!(!m.contains(TOKEN) && m.starts_with("HTTP 401:")),
        o => panic!("{o:?}"),
    }
}

// ---------- JSON gating ----------
#[test]
fn accepts_json_and_jsonapi_and_pretty_prints() {
    let out = require_json(200, Some("application/json; charset=utf-8"), br#"{"data":[]}"#).unwrap();
    assert_eq!(out, "{\n  \"data\": []\n}");
    assert!(require_json(200, Some("application/vnd.api+json"), b"{}").is_ok());
    assert!(require_json(200, Some("text/json"), b"{}").is_ok());
    assert!(require_json(200, Some("Application/JSON"), b"{}").is_ok());
    assert!(require_json(200, None, b"{}").is_err(), "missing content-type is refused");
    let weird = require_json(200, Some("text/html\r\nX-Injected: 1"), b"<html>{}</html>").unwrap_err();
    assert!(!weird.0.contains("X-Injected") && !weird.0.contains('\n'), "{weird}");
}

#[test]
fn refuses_non_json_types_and_bodies() {
    for (ct, body) in [
        (Some("text/html"), "<html>not json</html>"),
        (Some("text/plain"), "ok"),
        (Some("application/json"), "not-json{"),
        (Some("text/html"), r#"{"data":[]}"#),
        (Some("application/xml"), "{}"),
        (None, "<html>"),
        (Some("application/json"), ""),
    ] {
        let e = require_json(200, ct, body.as_bytes()).unwrap_err();
        assert!(e.0.contains("not JSON"), "{ct:?} {body}");
    }
}

#[test]
fn non_json_body_is_not_echoed() {
    let f = Fake::new(200, Some("text/html"), "<html>SECRETPAGE</html>");
    let e = perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap_err();
    assert!(!e.0.contains("SECRETPAGE"));
}

// ---------- perform: redirects, errors, no retries ----------
#[test]
fn redirects_are_refused() {
    for status in [301u16, 302, 303, 307, 308, 300, 399] {
        let f = Fake::new(status, Some("application/json"), "{}");
        let e = perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap_err();
        assert!(e.0.contains("redirect"), "{status}");
        assert_eq!(f.calls.borrow().len(), 1);
    }
}

#[test]
fn success_returns_json_with_single_call_and_auth_passed() {
    let f = Fake::new(200, Some("application/json"), r#"{"data":[{"id":"1"}]}"#);
    let out = perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap();
    assert!(matches!(out, Outcome::Success(ref t) if t.contains("\"id\": \"1\"")));
    let calls = f.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "https://api.hackerone.com/v1/hackers/programs");
    assert_eq!(calls[0].1, creds().basic_header());
}

#[test]
fn http_errors_surface_once_without_retry() {
    for status in [400u16, 401, 403, 404, 429, 500, 503] {
        let f = Fake::new(status, Some("application/json"), r#"{"errors":[{"detail":"missing"}]}"#);
        match perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap() {
            Outcome::HttpError(m) => {
                assert!(m.starts_with(&format!("HTTP {status}: ")));
                assert!(m.contains("missing"));
            }
            o => panic!("{o:?}"),
        }
        assert_eq!(f.calls.borrow().len(), 1);
    }
}

#[test]
fn http_error_non_json_refused() {
    let f = Fake::new(500, Some("text/html"), "<html>fail</html>");
    let e = perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap_err();
    assert!(e.0.contains("HTTP 500") && e.0.contains("not JSON"));
}

#[test]
fn http_error_text_is_truncated_to_2000_chars() {
    let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(5000));
    let f = Fake::new(500, Some("application/json"), &big);
    match perform(&f, &req("/v1/hackers/programs"), &creds()).unwrap() {
        Outcome::HttpError(m) => assert_eq!(m.chars().count(), "HTTP 500: ".len() + 2000),
        o => panic!("{o:?}"),
    }
}

#[test]
fn transport_error_is_propagated_without_second_call() {
    let f = Fake {
        calls: RefCell::new(vec![]),
        resp: RefCell::new(Some(Err(Refused(s("request failed: Dns"))))),
    };
    assert!(perform(&f, &req("/v1/hackers/programs"), &creds()).is_err());
    assert_eq!(f.calls.borrow().len(), 1);
}

#[test]
fn denied_path_never_reaches_transport() {
    // Validation is the only way to build a ValidatedRequest, so a denied path can't get a Fake call.
    let f = Fake::new(200, Some("application/json"), "{}");
    assert!(build_request("/v1/hackers/report_intents/1/submit", &[]).is_err());
    assert!(f.calls.borrow().is_empty());
}

#[test]
fn unexpected_1xx_is_refused() {
    let f = Fake::new(199, Some("application/json"), "{}");
    assert!(perform(&f, &req("/v1/hackers/programs"), &creds()).is_err());
}
