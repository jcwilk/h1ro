//! The ONLY module that touches the network.
//!
//! Safety properties (each is also covered by a unit test or the source-scan test):
//! - The sole HTTP call is `agent.get(url)`. No other verb method is used.
//! - No request body is ever sent.
//! - `redirects(0)`: redirects are never followed (a 3xx is refused upstream).
//! - `https_only(true)`: an `http://` URL is refused by the client.
//! - No proxy is configured; default features that would read a proxy from the environment are off.
//! - Response bodies are size-capped at 8 MiB.

use crate::{url_locked, RawResponse, Refused, Transport, ValidatedRequest};
use std::io::Read;
use std::time::Duration;

const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .https_only(true)
            .timeout(Duration::from_secs(30))
            .user_agent("h1ro/0.2 (read-only)")
            .build();
        Self { agent }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

fn read_all(resp: ureq::Response) -> Result<RawResponse, Refused> {
    let status = resp.status();
    let content_type = resp.header("Content-Type").map(str::to_string);
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| Refused(format!("refused: failed reading response: {e}")))?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(Refused("refused: response too large".into()));
    }
    Ok(RawResponse {
        status,
        content_type,
        body,
    })
}

impl Transport for UreqTransport {
    fn get(&self, request: &ValidatedRequest, auth_header: &str) -> Result<RawResponse, Refused> {
        // Last line of defence, independent of how the request was built.
        // Requires the byte after the host and `/v1/hackers` to be `/`, `?`, or the end,
        // so `api.hackerone.com.evil` cannot pass a prefix check.
        if !url_locked(request.url()) {
            return Err(Refused("refused: host is not api.hackerone.com".into()));
        }
        let result = self
            .agent
            .get(request.url())
            .set("Accept", "application/json")
            .set("Authorization", auth_header)
            .call();
        match result {
            Ok(resp) => read_all(resp),
            // ureq reports 4xx/5xx as Err(Status); surface them as ordinary responses.
            Err(ureq::Error::Status(_, resp)) => read_all(resp),
            Err(ureq::Error::Transport(t)) => {
                // Transport errors never include request headers; still no auth is echoed here.
                Err(Refused(format!("request failed: {}", t.kind())))
            }
        }
    }
}
