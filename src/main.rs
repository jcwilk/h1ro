use h1ro::cmd;
use h1ro::http::UreqTransport;
use h1ro::*;
use std::io::Write;
use std::process::ExitCode;

fn scrubbed(s: &str) -> String {
    let token = std::env::var("H1_API_TOKEN").unwrap_or_default();
    let user = std::env::var("H1_API_USERNAME").unwrap_or_else(|_| DEFAULT_USERNAME.to_string());
    scrub_secrets(&user, &token, s)
}

fn write_out(s: &str) {
    let s = scrubbed(s);
    let _ = std::io::stdout().lock().write_all(s.as_bytes());
}
fn write_err(s: &str) {
    let s = scrubbed(s);
    let _ = std::io::stderr().lock().write_all(s.as_bytes());
}

/// Raw-path mode: EXACTLY the pre-subcommand behaviour (`h1ro [--dry-run] /v1/hackers/... [k=v ...]`).
fn run_raw_path_mode(args: &[String]) -> Result<ExitCode, Refused> {
    match parse_args(args)? {
        Cli::NoArgs | Cli::Help => {
            write_out(cmd::OVERVIEW);
            Ok(ExitCode::SUCCESS)
        }
        Cli::Run {
            dry_run,
            path,
            params,
        } => {
            let path = validate_path(&path)?;
            let params = validate_params(&params)?;
            let req = build_request(&path, &params)?;
            if dry_run {
                let (c, shown) = creds_and_user();
                write_out(&dry_run_text(&req, &shown, c.is_ok()));
                return Ok(ExitCode::SUCCESS);
            }
            let creds = Credentials::from_env()?;
            let transport = UreqTransport::new();
            match perform(&transport, &req, &creds) {
                Ok(Outcome::Success(text)) => {
                    write_out(&text);
                    write_out("\n");
                    Ok(ExitCode::SUCCESS)
                }
                Ok(Outcome::HttpError(msg)) => {
                    write_err(&format!("{msg}\n"));
                    Ok(ExitCode::from(1))
                }
                Err(e) => Err(Refused(creds.scrub(&e.0))),
            }
        }
    }
}

fn creds_and_user() -> (Result<Credentials, Refused>, String) {
    let creds = Credentials::from_env();
    let user = std::env::var("H1_API_USERNAME").unwrap_or_else(|_| DEFAULT_USERNAME.to_string());
    let shown = match &creds {
        Ok(c) => c.username().to_string(),
        Err(_) => user.chars().filter(|c| !c.is_control()).collect(),
    };
    (creds, shown)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Backward-compat rule: if the first non-flag argument starts with `/`, the whole
    // invocation is raw-path mode, handled exactly as before subcommands existed.
    let raw_mode = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map_or(false, |a| a.starts_with('/'));
    if raw_mode {
        return match run_raw_path_mode(&args) {
            Ok(code) => code,
            Err(e) => {
                write_err(&format!("{e}\n"));
                ExitCode::from(1)
            }
        };
    }
    let (creds, shown) = creds_and_user();
    let transport = UreqTransport::new();
    let (mut out, mut err) = (String::new(), String::new());
    let code = cmd::execute(&args, &creds, &shown, &transport, &mut out, &mut err);
    write_out(&out);
    write_err(&err);
    ExitCode::from(code as u8)
}
