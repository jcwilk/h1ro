use crate::cmd::*;
use crate::*;
use std::cell::RefCell;

const TOKEN: &str = "SECRET-TOKEN-abc123XYZ";

fn v(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}
fn creds() -> Result<Credentials, Refused> {
    Credentials::new("tester", TOKEN)
}

struct Fake {
    calls: RefCell<Vec<String>>,
    status: u16,
    body: String,
}
impl Fake {
    fn ok(body: &str) -> Self {
        Fake { calls: RefCell::new(vec![]), status: 200, body: body.to_string() }
    }
    fn calls(&self) -> usize {
        self.calls.borrow().len()
    }
}
impl Transport for Fake {
    fn get(&self, r: &ValidatedRequest, _auth: &str) -> Result<RawResponse, Refused> {
        self.calls.borrow_mut().push(r.url().to_string());
        Ok(RawResponse {
            status: self.status,
            content_type: Some("application/json".into()),
            body: self.body.clone().into_bytes(),
        })
    }
}

fn run(args: &[&str], f: &Fake) -> (i32, String, String) {
    let (mut out, mut err) = (String::new(), String::new());
    let code = execute(&v(args), &creds(), "tester", f, &mut out, &mut err);
    (code, out, err)
}

fn url_of(args: &[&str]) -> String {
    match plan(&v(args)).unwrap() {
        Plan::Request(p) => p.req.url().to_string(),
        Plan::Text(t) => panic!("expected request, got text: {t}"),
    }
}

const PROGRAMS: &str = r#"{"data":[
 {"id":"13","type":"program","attributes":{"handle":"security","name":"HackerOne","offers_bounties":true,"state":"public_mode","submission_state":"open","policy":"line1\nline2\tTAB and a very long policy text that goes on and on and on and on and on and on and on and on and on"}},
 {"id":"14","type":"program","attributes":{"handle":"vdp","name":"A VDP","offers_bounties":false,"state":"public_mode","submission_state":"open","policy":"short"}}
],"links":{"self":"https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=2","next":"https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2&page%5Bsize%5D=2","last":"https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=6&page%5Bsize%5D=2"}}"#;

// ---------- mapping: every subcommand -> exact allowed GET ----------
#[test]
fn every_subcommand_maps_to_expected_get() {
    let h = "https://api.hackerone.com/v1/hackers";
    let cases: Vec<(Vec<&str>, String)> = vec![
        (vec!["programs", "list"], format!("{h}/programs")),
        (vec!["programs", "list", "--limit", "2"], format!("{h}/programs?page%5Bsize%5D=2")),
        (vec!["programs", "list", "--limit=2", "--page=3"], format!("{h}/programs?page%5Bsize%5D=2&page%5Bnumber%5D=3")),
        (vec!["programs", "get", "dyson"], format!("{h}/programs/dyson")),
        (vec!["programs", "scopes", "dyson", "--limit", "3"], format!("{h}/programs/dyson/structured_scopes?page%5Bsize%5D=3")),
        (vec!["programs", "weaknesses", "dyson"], format!("{h}/programs/dyson/weaknesses")),
        (vec!["programs", "exclusions", "dyson"], format!("{h}/programs/dyson/scope_exclusions")),
        (vec!["reports", "list", "--page", "2"], format!("{h}/me/reports?page%5Bnumber%5D=2")),
        (vec!["reports", "get", "4149145"], format!("{h}/reports/4149145")),
        (vec!["raw", "/v1/hackers/me"], format!("{h}/me")),
        (vec!["hacktivity", "--limit", "5"], format!("{h}/hacktivity?page%5Bsize%5D=5")),
        (
            vec!["hacktivity", "--query", "severity_rating:critical AND disclosed:true", "--sort", "-disclosed_at"],
            format!("{h}/hacktivity?queryString=severity_rating%3Acritical%20AND%20disclosed%3Atrue&sort=-disclosed_at"),
        ),
        (
            vec!["hacktivity", "--query", "a&page[size]=9"],
            format!("{h}/hacktivity?queryString=a%26page%5Bsize%5D%3D9"),
        ),
        (
            vec!["programs", "scopes", "dyson", "--since-id", "10", "--created-after", "2024-01-01T00:00:00Z", "--updated-after", "2024-06-01", "--limit", "5"],
            format!("{h}/programs/dyson/structured_scopes?filter%5Bid__gt%5D=10&filter%5Bcreated_at__gt%5D=2024-01-01T00%3A00%3A00Z&filter%5Bupdated_at__gt%5D=2024-06-01&page%5Bsize%5D=5"),
        ),
        (vec!["payments", "balance"], format!("{h}/payments/balance")),
        (vec!["payments", "earnings"], format!("{h}/payments/earnings")),
        (vec!["payments", "payouts"], format!("{h}/payments/payouts")),
        (vec!["intents", "list"], format!("{h}/report_intents")),
        (vec!["intents", "get", "23"], format!("{h}/report_intents/23")),
        (vec!["intents", "attachments", "23"], format!("{h}/report_intents/23/attachments")),
        (vec!["raw", "/v1/hackers/programs", "page[size]=1"], format!("{h}/programs?page%5Bsize%5D=1")),
        (vec!["--json", "programs", "get", "dyson"], format!("{h}/programs/dyson")),
        (vec!["programs", "get", "dyson", "--dry-run"], format!("{h}/programs/dyson")),
    ];
    for (args, want) in cases {
        assert_eq!(url_of(&args), want, "{args:?}");
    }
}

#[test]
fn every_spec_endpoint_text_is_a_hackers_get() {
    for s in SPECS {
        let e = s.endpoint.strip_prefix("GET ").expect(s.name);
        assert!(e.starts_with("/v1/hackers") || e.starts_with("<path>"), "{}: {e}", s.name);
        assert!(!s.endpoint.to_ascii_uppercase().contains("POST"));
    }
    assert_eq!(SPECS.len(), 15);
    for s in SPECS {
        assert!(!s.endpoint.contains("POST") && !s.endpoint.contains("PATCH") && !s.endpoint.contains("DELETE"), "{}", s.name);
    }
}

#[test]
fn every_kind_path_for_passes_validator_for_a_normal_arg() {
    for s in SPECS {
        if s.kind == Kind::Raw {
            continue;
        }
        let p = path_for(s.kind, "dyson");
        assert_eq!(validate_path(&p).unwrap(), p, "{}", s.name);
        assert!(p.starts_with("/v1/hackers"));
    }
}

// ---------- hostile arguments: refused by the VALIDATOR, not only by the builder ----------
#[test]
fn validator_itself_refuses_hostile_handles_and_ids() {
    let evil = [
        "../invitations",
        "x/submit",
        "..",
        ".",
        "%2e%2e",
        "a%2fb",
        "a b",
        "a?b=1",
        "a#b",
        "https://evil.example",
        "//evil.example",
        "x/../../programs",
        "x\\y",
        "a\nb",
        "",
        "invitations",
        "mark_read",
        "x/token",
        "caf\u{e9}",
    ];
    for kind in [
        Kind::ProgramsGet,
        Kind::ProgramsScopes,
        Kind::ProgramsWeaknesses,
        Kind::ProgramsExclusions,
        Kind::ReportsGet,
        Kind::IntentsGet,
        Kind::IntentsAttachments,
    ] {
        for e in evil {
            let p = path_for(kind, e); // unchecked formatter
            assert!(validate_path(&p).is_err(), "validator accepted {p:?}");
        }
    }
}

#[test]
fn planner_refuses_hostile_args_and_builds_no_request() {
    for e in ["../invitations", "x/submit", "x/y", "%2e%2e", "a b", "https://evil.example", "x?y", ""] {
        for cmd in [
            vec!["programs", "get"],
            vec!["programs", "scopes"],
            vec!["programs", "weaknesses"],
            vec!["programs", "exclusions"],
            vec!["reports", "get"],
            vec!["intents", "get"],
            vec!["intents", "attachments"],
        ] {
            let mut a = cmd.clone();
            a.push(e);
            assert!(plan(&v(&a)).is_err(), "{a:?}");
        }
    }
    assert!(plan(&v(&["reports", "get", "12abc"])).is_err());
    assert!(plan(&v(&["reports", "get", "-1"])).is_err());
    assert!(plan(&v(&["intents", "get", "12abc"])).is_err());
    assert!(plan(&v(&["intents", "get", "1/submit"])).is_err());
    assert!(plan(&v(&["intents", "attachments", "23", "9"])).is_err());
    assert!(plan(&v(&["intents", "attachments", "23/9"])).is_err());
    assert!(plan(&v(&["raw", "/v1/hackers/report_intents/23/attachments/9"])).is_err());
    let f = Fake::ok("{}");
    let (code, out, err) = run(&["programs", "scopes", "../invitations"], &f);
    assert_eq!(code, 1);
    assert!(out.is_empty());
    assert!(err.starts_with("refused:"), "{err}");
    assert_eq!(f.calls(), 0);
}

#[test]
fn raw_subcommand_uses_same_validator() {
    for p in [
        "/v1/programs/x",
        "/v1/hackers/invitations",
        "/v1/hackers/report_intents/1/submit",
        "https://api.hackerone.com/v1/hackers/programs",
        "programs",
        "/v1/hackers/../programs",
        "/v1/hackers/me%2f",
        "-x",
    ] {
        assert!(plan(&v(&["raw", p])).is_err(), "{p}");
    }
    assert!(plan(&v(&["raw", "/v1/hackers/programs", "token=1"])).is_err());
    assert!(plan(&v(&["raw", "/v1/hackers/programs", "export=1"])).is_err());
    assert!(plan(&v(&["raw"])).is_err());
}

#[test]
fn builders_cannot_leave_the_lock_for_any_input_shape() {
    // Fuzz-ish: for many argument strings, any planned request URL is under the lock.
    let junk = ["a", "a-b", "a.b", "..", "a/b", "a/../b", "%00", "x y", "\u{0}", "@", "x@y", "x:y", "?", "#", "\\", "//", "v1", "/v1/hackers"];
    for j in junk {
        for cmd in [vec!["programs", "get"], vec!["programs", "scopes"], vec!["reports", "get"], vec!["intents", "get"], vec!["intents", "attachments"], vec!["raw"]] {
            let mut a = cmd.clone();
            a.push(j);
            if let Ok(Plan::Request(p)) = plan(&v(&a)) {
                assert!(
                    p.req.url() == "https://api.hackerone.com/v1/hackers"
                        || p.req.url().starts_with("https://api.hackerone.com/v1/hackers/"),
                    "{a:?} -> {}",
                    p.req.url()
                );
            }
        }
    }
}

// ---------- flags / parsing ----------
#[test]
fn flag_validation() {
    for bad in [
        vec!["programs", "list", "--limit", "0"],
        vec!["programs", "list", "--limit", "101"],
        vec!["programs", "list", "--limit", "x"],
        vec!["programs", "list", "--limit"],
        vec!["programs", "list", "--page", "0"],
        vec!["programs", "list", "--fields", "a,,b"],
        vec!["programs", "list", "--fields", "a b"],
        vec!["programs", "list", "--fields", "page[size]"],
        vec!["programs", "list", "--method", "POST"],
        vec!["programs", "list", "-X", "POST"],
        vec!["programs", "list", "--json=1"],
        vec!["programs", "get", "dyson", "--limit", "2"], // not paginated
        vec!["programs", "get", "dyson", "--page", "2"],
        vec!["programs", "scopes", "dyson", "--bounty-only"],
        vec!["me"],
        vec!["raw", "/v1/hackers/programs", "--limit", "1"],
        vec!["programs", "list", "--query", "x"],
        vec!["programs", "list", "--sort", "-votes"],
        vec!["programs", "scopes", "dyson", "--query", "x"],
        vec!["hacktivity", "--sort", "submit"],
        vec!["hacktivity", "--sort", "votes;DELETE"],
        vec!["hacktivity", "--query", ""],
        vec!["programs", "scopes", "dyson", "--created-after", "2024-01-01;drop"],
        vec!["programs", "scopes", "dyson", "--updated-after", "yesterday"],
        vec!["intents", "list", "--limit", "10"],
        vec!["intents", "attachments", "23", "--page", "2"],
        vec!["programs", "list", "extra"],
        vec!["programs", "get"],
        vec!["programs", "get", "a", "b"],
        vec!["programs", "nope"],
        vec!["nope"],
        vec!["--json"],
    ] {
        let e = plan(&v(&bad)).unwrap_err();
        assert!(e.0.starts_with("error:") || e.0.starts_with("refused:"), "{bad:?}: {e}");
    }
}

// ---------- discovery ----------
#[test]
fn discovery_overview_groups_and_details() {
    for a in [vec![], vec!["help"], vec!["--help"], vec!["-h"]] {
        match plan(&v(&a)).unwrap() {
            Plan::Text(t) => {
                assert_eq!(t, OVERVIEW);
                for w in ["programs", "reports", "payments", "intents", "hacktivity", "raw", "--json", "--dry-run", "--help", "/v1/hackers"] {
                    assert!(t.contains(w), "{w}");
                }
                assert!(t.lines().all(|l| !l.trim_start().starts_with("me ")), "{t}");
                assert!(t.lines().count() <= 24, "overview must stay compact");
            }
            _ => panic!(),
        }
    }
    match plan(&v(&["programs"])).unwrap() {
        Plan::Text(t) => {
            for s in ["list", "get", "scopes", "weaknesses", "exclusions"] {
                assert!(t.contains(s));
            }
            assert!(!t.contains("reports get"));
        }
        _ => panic!(),
    }
    // detailed help names the exact endpoint and has an example
    for (a, ep) in [
        (vec!["programs", "scopes", "--help"], "GET /v1/hackers/programs/<handle>/structured_scopes"),
        (vec!["programs", "get", "-h"], "GET /v1/hackers/programs/<handle>"),
        (vec!["help", "reports", "get"], "GET /v1/hackers/reports/<id>"),
        (vec!["reports", "list", "--help"], "GET /v1/hackers/me/reports"),
        (vec!["intents", "list", "--help"], "GET /v1/hackers/report_intents"),
        (vec!["intents", "attachments", "--help"], "GET /v1/hackers/report_intents/<id>/attachments"),
        (vec!["hacktivity", "--help"], "queryString"),
        (vec!["programs", "scopes", "--help"], "filter[id__gt]"),
        (vec!["programs", "list", "--help"], "client-side"),
        (vec!["raw", "--help"], "GET <path>"),
    ] {
        match plan(&v(&a)).unwrap() {
            Plan::Text(t) => {
                assert!(t.contains(ep), "{a:?}: {t}");
                assert!(t.contains("example:"), "{a:?}");
            }
            _ => panic!("{a:?}"),
        }
    }
    // help never plans a request even with a hostile handle present
    assert!(matches!(plan(&v(&["programs", "get", "../x", "--help"])).unwrap(), Plan::Text(_)));
}

// ---------- compact output ----------
#[test]
fn programs_list_compact_columns_header_and_truncation() {
    let f = Fake::ok(PROGRAMS);
    let (code, out, err) = run(&["programs", "list", "--limit", "2", "--max-chars", "11"], &f);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "handle\tname\toffers_bounties\tstate\tsubmission_state");
    assert_eq!(lines[1], "security\tHackerOne\ttrue\tpublic_mode\topen");
    assert_eq!(lines[2], "vdp\tA VDP\tfalse\tpublic_mode\topen");
    assert_eq!(lines.len(), 3);
    assert!(lines.iter().all(|l| l.matches('\t').count() == 4));
    assert!(!out.contains(TOKEN));
    assert_eq!(f.calls(), 1);
    assert_eq!(
        err,
        "# programs list: 2 rows; page 1 of 6 (size 2); next: h1ro programs list --max-chars 11 --limit 2 --page 2\n"
    );
}

#[test]
fn fields_flag_truncation_marker_and_escaping() {
    let f = Fake::ok(PROGRAMS);
    let (code, out, err) = run(&["programs", "list", "--fields", "handle,policy", "--max-chars", "12"], &f);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "handle\tpolicy");
    assert!(lines[1].starts_with("security\tline1\\nline2…[+") && lines[1].ends_with(" chars]"), "{}", lines[1]);
    assert!(lines[1].contains("…[+"), "{}", lines[1]);
    assert!(lines[1].contains("\\n"));
    assert_eq!(lines[2], "vdp\tshort");
    assert!(err.contains("1 cell(s) truncated at 12 chars; full: --json, or --max-chars 0"), "{err}");
    // unlimited
    let f2 = Fake::ok(PROGRAMS);
    let (_, out2, err2) = run(&["programs", "list", "--fields", "policy", "--max-chars", "0"], &f2);
    assert!(out2.contains("line1\\nline2\\tTAB and a very long"));
    assert!(out2.contains("on and on and on and on and on and on and on and on and on"));
    assert!(!err2.contains("truncated"));
    // unknown field
    let f3 = Fake::ok(PROGRAMS);
    let (c3, o3, e3) = run(&["programs", "list", "--fields", "nope"], &f3);
    assert_eq!(c3, 1);
    assert!(o3.is_empty());
    assert!(e3.starts_with("error: unknown field 'nope' (available: id,"), "{e3}");
}

#[test]
fn bounty_only_is_client_side_and_documented_in_footer() {
    let f = Fake::ok(PROGRAMS);
    let (code, out, err) = run(&["programs", "list", "--bounty-only", "--limit", "2"], &f);
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 2);
    assert!(out.contains("security") && !out.contains("vdp"));
    assert!(err.contains("1 of 2 rows kept (--bounty-only is a client-side filter"), "{err}");
    assert!(err.contains("next: h1ro programs list --bounty-only --limit 2 --page 2"), "{err}");
    // the request itself carries no filter parameter
    assert_eq!(f.calls.borrow()[0], "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=2");
}

#[test]
fn footer_without_known_size_or_last_page_or_next() {
    let body = r#"{"data":[{"id":"1","type":"program","attributes":{"handle":"a","name":"A","offers_bounties":true,"state":"s","submission_state":"open"}}],"links":{"self":"https://api.hackerone.com/v1/hackers/programs"}}"#;
    let (code, _, err) = run(&["programs", "list"], &Fake::ok(body));
    assert_eq!(code, 0);
    assert_eq!(err, "# programs list: 1 rows; page 1 (size: API default, not reported); end of results\n");
    let body2 = body.replace(r#"{"self":"https://api.hackerone.com/v1/hackers/programs"}"#, r#"{"self":"https://api.hackerone.com/v1/hackers/programs","next":"https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2"}"#);
    let (_, _, err2) = run(&["programs", "list"], &Fake::ok(&body2));
    assert!(err2.contains("next: h1ro programs list --page 2"), "{err2}");
    assert!(!err2.contains("--limit"), "{err2}");
}

#[test]
fn scopes_columns_and_next_hint_keeps_handle() {
    let body = r#"{"data":[{"id":"9013","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"*.dyson.com","eligible_for_bounty":true,"eligible_for_submission":true,"instruction":"x","max_severity":"critical"}}],
      "links":{"self":"https://api.hackerone.com/v1/hackers/programs/dyson/structured_scopes?page%5Bsize%5D=1","next":"https://api.hackerone.com/v1/hackers/programs/dyson/structured_scopes?page%5Bnumber%5D=2&page%5Bsize%5D=1","last":"https://api.hackerone.com/v1/hackers/programs/dyson/structured_scopes?page%5Bnumber%5D=49&page%5Bsize%5D=1"}}"#;
    let (code, out, err) = run(&["programs", "scopes", "dyson", "--limit", "1"], &Fake::ok(body));
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "asset_type\tasset_identifier\teligible_for_bounty\teligible_for_submission\tmax_severity\nURL\t*.dyson.com\ttrue\ttrue\tcritical\n"
    );
    assert_eq!(
        err,
        "# programs scopes: 1 rows; page 1 of 49 (size 1); next: h1ro programs scopes dyson --limit 1 --page 2\n"
    );
}

#[test]
fn reports_list_columns_and_get_kv_view() {
    let body = r#"{"data":[{"id":"7","type":"report","attributes":{"title":"T","state":"duplicate","created_at":"2026-01-01","bounty_awarded_at":null,"vulnerability_information":"body"},"relationships":{"program":{"data":{"type":"program","attributes":{"handle":"dyson"}}}}}],"links":{"self":"https://api.hackerone.com/v1/hackers/me/reports?page%5Bsize%5D=1"}}"#;
    let (_, out, _) = run(&["reports", "list"], &Fake::ok(body));
    assert_eq!(out, "id\tstate\tcreated_at\tbounty_awarded_at\ttitle\tprogram\n7\tduplicate\t2026-01-01\tnull\tT\tdyson\n");
    let one = r#"{"data":{"id":"7","type":"report","attributes":{"title":"T","vulnerability_information":"0123456789ABCDEF"},"relationships":{"reporter":{},"program":{}}}}"#;
    let (code, out, err) = run(&["reports", "get", "7", "--max-chars", "6"], &Fake::ok(one));
    assert_eq!(code, 0);
    assert_eq!(out, "id\t7\ntype\treport\ntitle\tT\nvulnerability_information\t012345…[+10 chars]\n");
    assert!(err.contains("1 value(s) truncated at 6 chars") && err.contains("relationships omitted: reporter,program"), "{err}");
}

#[test]
fn report_get_prints_included_activities_and_does_not_fetch_files() {
    let one = r#"{"data":{"id":"7","type":"report","attributes":{"title":"T","vulnerability_information":"body"},"relationships":{"program":{"data":{"attributes":{"handle":"dyson"}}},"activities":{"data":[{"type":"activity-comment","attributes":{"message":"hello there","created_at":"2026-01-02T00:00:00.000Z"},"relationships":{"actor":{"data":{"attributes":{"username":"triage"}}},"attachments":{"data":[{"id":"9","type":"attachment","attributes":{"file_name":"shot.png","content_type":"image/png","file_size":12,"expiring_url":"https://attachments.example/secret"}}]}}}]}}}}"#;
    let f = Fake::ok(one);
    let (code, out, err) = run(&["reports", "get", "7"], &f);
    assert_eq!(code, 0);
    assert!(out.contains("title\tT\n"), "{out}");
    assert!(out.contains("created_at\ttype\tactor\tmessage\n"), "{out}");
    assert!(out.contains("2026-01-02T00:00:00.000Z\tactivity-comment\ttriage\thello there\n"), "{out}");
    assert!(out.contains("id\tfile_name\tcontent_type\tfile_size\texpiring_url\n"), "{out}");
    assert!(out.contains("9\tshot.png\timage/png\t12\thttps://attachments.example/secret\n"), "{out}");
    assert!(err.contains("activities: 1"), "{err}");
    assert!(err.contains("attachments: 1 (not downloaded)"), "{err}");
    assert!(err.contains("relationships omitted: program"), "{err}");
    assert!(!err.contains("activities,") && !err.contains("omitted: activities"), "{err}");
    assert_eq!(f.calls(), 1);
    assert!(f.calls.borrow()[0].starts_with("https://api.hackerone.com/v1/hackers/reports/7"));
}

#[test]
fn intent_attachment_metadata_includes_the_url_without_fetching_it() {
    let body = r#"{"data":[{"id":"9","type":"attachment","attributes":{"expiring_url":"https://hackerone.com/url/to/attachment","created_at":"2025-09-25T13:01:28.293Z","file_name":"a.png","content_type":"image/png","file_size":12}}]}"#;
    let f = Fake::ok(body);
    let (code, out, err) = run(&["intents", "attachments", "23"], &f);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "id\tfile_name\tcontent_type\tfile_size\tcreated_at\texpiring_url\n9\ta.png\timage/png\t12\t2025-09-25T13:01:28.293Z\thttps://hackerone.com/url/to/attachment\n"
    );
    assert!(err.contains("1 rows"), "{err}");
    assert_eq!(f.calls.borrow()[0], "https://api.hackerone.com/v1/hackers/report_intents/23/attachments");
    let (_, json, _) = run(&["intents", "attachments", "23", "--json"], &Fake::ok(body));
    assert!(json.contains("expiring_url"));
}

#[test]
fn next_hint_keeps_read_filters_and_quotes_the_query() {
    let body = r#"{"data":[],"links":{"self":"https://api.hackerone.com/v1/hackers/hacktivity?page%5Bsize%5D=1","next":"https://api.hackerone.com/v1/hackers/hacktivity?page%5Bnumber%5D=2&page%5Bsize%5D=1"}}"#;
    let (_, _, err) = run(
        &["hacktivity", "--query", "it's a test", "--sort", "-votes", "--limit", "1"],
        &Fake::ok(body),
    );
    assert!(err.contains("next: h1ro hacktivity --query 'it'\\''s a test' --sort -votes --limit 1 --page 2\n") || err.contains("--query 'it'\\''s a test'"), "{err}");
    assert!(err.contains("--sort -votes"), "{err}");
    let scopes = r#"{"data":[],"links":{"next":"https://api.hackerone.com/v1/hackers/programs/dyson/structured_scopes?page%5Bnumber%5D=2&page%5Bsize%5D=1"}}"#;
    let (_, _, err2) = run(
        &["programs", "scopes", "dyson", "--since-id", "10", "--created-after", "2024-01-01T00:00:00Z", "--limit", "1"],
        &Fake::ok(scopes),
    );
    assert!(err2.contains("--since-id 10"), "{err2}");
    assert!(err2.contains("--created-after 2024-01-01T00:00:00Z"), "{err2}");
    assert!(err2.contains("--page 2"), "{err2}");
}

#[test]
fn programs_get_handles_top_level_object_shape() {
    let body = r#"{"id":"1","type":"program","attributes":{"handle":"dyson","policy":"abc"},"relationships":{}}"#;
    let (code, out, _) = run(&["programs", "get", "dyson"], &Fake::ok(body));
    assert_eq!(code, 0);
    assert_eq!(out, "id\t1\ntype\tprogram\nhandle\tdyson\npolicy\tabc\n");
}

#[test]
fn balance_flat_object_renders_kv() {
    let (_, out, _) = run(&["payments", "balance"], &Fake::ok(r#"{"data":{"balance":0.0}}"#));
    assert_eq!(out, "balance\t0.0\n");
}

#[test]
fn json_mode_round_trips_full_response() {
    let f = Fake::ok(PROGRAMS);
    let (code, out, _) = run(&["programs", "list", "--json"], &f);
    assert_eq!(code, 0);
    let a: serde_json::Value = serde_json::from_str(&out).unwrap();
    let b: serde_json::Value = serde_json::from_str(PROGRAMS).unwrap();
    assert_eq!(a, b);
    assert!(out.contains("\n  \"data\""), "pretty printed");
    // --json ignores bounty-only filter and says so
    let (_, out2, err2) = run(&["programs", "list", "--json", "--bounty-only"], &Fake::ok(PROGRAMS));
    assert!(out2.contains("\"vdp\""));
    assert!(err2.contains("--bounty-only ignored with --json"));
    // get --json
    let one = r#"{"id":"1","type":"program","attributes":{"policy":"x"}}"#;
    let (_, o, _) = run(&["programs", "get", "dyson", "--json"], &Fake::ok(one));
    assert_eq!(serde_json::from_str::<serde_json::Value>(&o).unwrap(), serde_json::from_str::<serde_json::Value>(one).unwrap());
}

#[test]
fn empty_lists_keep_documented_headers() {
    let empty = r#"{"data":[],"links":{}}"#;
    let (c, out, _) = run(&["programs", "exclusions", "dyson"], &Fake::ok(empty));
    assert_eq!(c, 0);
    assert_eq!(out, "id\tcategory\tdetails\tcreated_at\tupdated_at\n");
    let (_, out, _) = run(&["payments", "earnings"], &Fake::ok(empty));
    assert_eq!(out, "id\ttype\tamount\tcreated_at\tprogram\n");
    let (_, out, _) = run(&["payments", "payouts"], &Fake::ok(empty));
    assert_eq!(out, "amount\tpaid_out_at\tstatus\tpayout_provider\treference\n");
    let payout = r#"{"data":[{"amount":100,"paid_out_at":"2016-02-02T04:05:06.000Z","reference":"ref","payout_provider":"PayPal","status":"sent"}],"links":{}}"#;
    let (_, out, _) = run(&["payments", "payouts"], &Fake::ok(payout));
    assert!(out.contains("100\t2016-02-02T04:05:06.000Z\tsent\tPayPal\tref\n"), "{out}");
}

fn raw_subcommand_prints_pretty_json_and_next_hint() {
    let (code, out, err) = run(&["raw", "/v1/hackers/programs", "page[size]=2"], &Fake::ok(PROGRAMS));
    assert_eq!(code, 0);
    assert!(out.starts_with("{\n  \"data\""));
    assert!(err.contains("next: h1ro raw /v1/hackers/programs 'page[size]=2' 'page[number]=2'"), "{err}");
}

// ---------- errors ----------
#[test]
fn http_error_is_error_prefixed_and_nonzero() {
    let f = Fake { calls: RefCell::new(vec![]), status: 401, body: r#"{"errors":[{"status":401,"detail":"nope"}]}"#.into() };
    let (code, out, err) = run(&["programs", "get", "dyson"], &f);
    assert_eq!(code, 1);
    assert!(out.is_empty());
    assert!(err.starts_with("error: HTTP 401: "), "{err}");
    assert_eq!(f.calls(), 1);
    assert!(plan(&v(&["me"])).is_err());
}

#[test]
fn missing_token_is_error_and_makes_no_call() {
    let f = Fake::ok("{}");
    let (mut out, mut err) = (String::new(), String::new());
    let code = execute(&v(&["programs", "list"]), &Credentials::new("u", ""), "u", &f, &mut out, &mut err);
    assert_eq!(code, 1);
    assert_eq!(err, "error: H1_API_TOKEN not set\n");
    assert_eq!(f.calls(), 0);
}

#[test]
fn redirect_and_non_json_are_refused() {
    let f = Fake { calls: RefCell::new(vec![]), status: 302, body: "{}".into() };
    let (code, out, err) = run(&["programs", "list"], &f);
    assert_eq!((code, out.is_empty()), (1, true));
    assert!(err.contains("redirect"), "{err}");
    let f2 = Fake { calls: RefCell::new(vec![]), status: 200, body: "<html>".into() };
    let (c2, o2, e2) = run(&["programs", "list"], &f2);
    assert_eq!((c2, o2.is_empty()), (1, true));
    assert!(e2.contains("not JSON"));
}

// ---------- dry-run ----------
#[test]
fn dry_run_scrubs_a_token_placed_in_the_query() {
    let f = Fake::ok("{}");
    let (code, out, err) = run(&["hacktivity", "--query", TOKEN, "--dry-run"], &f);
    assert_eq!(code, 0, "{err}");
    assert_eq!(f.calls(), 0);
    assert!(!out.contains(TOKEN) && !err.contains(TOKEN), "{out} {err}");
    assert!(out.contains("queryString=<redacted>"), "{out}");
    assert!(out.contains("no network call made"));
}

#[test]
fn dry_run_every_subcommand_no_network_no_token() {
    let all: Vec<Vec<&str>> = vec![
        vec!["programs", "list", "--limit", "2"],
        vec!["programs", "get", "dyson"],
        vec!["programs", "scopes", "dyson", "--limit", "3"],
        vec!["programs", "weaknesses", "dyson"],
        vec!["programs", "exclusions", "dyson"],
        vec!["reports", "list"],
        vec!["reports", "get", "1"],
        vec!["hacktivity", "--query", "team:gitlab", "--sort", "-votes"],
        vec!["payments", "balance"],
        vec!["intents", "list"],
        vec!["intents", "get", "23"],
        vec!["intents", "attachments", "23"],
        vec!["programs", "scopes", "dyson", "--since-id", "10", "--created-after", "2024-01-01T00:00:00Z"],
        vec!["payments", "earnings"],
        vec!["payments", "payouts"],
        vec!["raw", "/v1/hackers/programs", "page[size]=1"],
    ];
    for mut a in all {
        a.push("--dry-run");
        let f = Fake::ok("{}");
        let (code, out, err) = run(&a, &f);
        assert_eq!(code, 0, "{a:?}: {err}");
        assert_eq!(f.calls(), 0, "{a:?}");
        assert!(out.contains("Would GET https://api.hackerone.com/v1/hackers"), "{a:?}");
        assert!(out.contains("no network call made"));
        assert!(!out.contains(TOKEN) && !err.contains(TOKEN));
        assert!(!out.contains(&creds().unwrap().basic_header()));
        assert!(err.is_empty());
    }
    // dry-run still refuses hostile input
    let f = Fake::ok("{}");
    let (code, out, err) = run(&["programs", "scopes", "x/submit", "--dry-run"], &f);
    assert_eq!(code, 1);
    assert!(out.is_empty() && err.starts_with("refused:"));
}

#[test]
fn token_never_in_any_output_even_if_api_echoes_it() {
    let body = format!(r#"{{"data":[{{"id":"1","type":"program","attributes":{{"handle":"{TOKEN}","name":"n","offers_bounties":true,"state":"s","submission_state":"o"}}}}],"links":{{}}}}"#);
    let (code, out, err) = run(&["programs", "list"], &Fake::ok(&body));
    assert_eq!(code, 0);
    assert!(!out.contains(TOKEN) && !err.contains(TOKEN));
    let (_, out2, _) = run(&["programs", "list", "--json"], &Fake::ok(&body));
    assert!(!out2.contains(TOKEN));
}

// ---------- backward compat: raw path mode ----------
#[test]
fn legacy_raw_path_mode_parse_unchanged() {
    match parse_args(&v(&["/v1/hackers/programs", "page[size]=1"])).unwrap() {
        Cli::Run { dry_run, path, params } => {
            assert!(!dry_run);
            assert_eq!(path, "/v1/hackers/programs");
            assert_eq!(params, v(&["page[size]=1"]));
        }
        o => panic!("{o:?}"),
    }
    match parse_args(&v(&["--dry-run", "/v1/hackers/me/programs", "page[size]=100"])).unwrap() {
        Cli::Run { dry_run, path, .. } => assert!(dry_run && path == "/v1/hackers/me/programs"),
        o => panic!("{o:?}"),
    }
    // legacy still refuses everything it refused before
    assert!(parse_args(&v(&["-X", "POST", "/v1/hackers/programs"])).is_err());
    assert!(validate_path("/v1/hackers/invitations").is_err());
    let r = build_request("/v1/hackers/programs", &validate_params(&v(&["page[size]=1"])).unwrap()).unwrap();
    assert_eq!(r.url(), "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1");
}

#[test]
fn main_dispatch_rule_is_documented_in_source() {
    // The dispatch rule lives in main.rs: first non-flag arg starting with '/' => raw path mode.
    let main = include_str!("main.rs");
    assert!(main.contains("starts_with('/')"));
    assert!(main.contains("run_raw_path_mode"));
}

// ---------- source-level safety scans for the new modules ----------
#[test]
fn new_modules_have_no_network_env_or_process_access() {
    for (name, src) in [("cmd.rs", include_str!("cmd.rs")), ("render.rs", include_str!("render.rs"))] {
        for bad in ["ureq", "std::net", "TcpStream", "env::", "Command", "std::process", "reqwest", "hyper", "std::fs", "File::"] {
            assert!(!src.contains(bad), "{name} contains {bad}");
        }
    }
    // Only perform()/Transport::get is used for network I/O from the command layer.
    let cmd = include_str!("cmd.rs");
    assert!(cmd.contains("perform(transport"));
    assert!(!cmd.contains(".post(") && !cmd.contains(".put(") && !cmd.contains(".delete("));
}
