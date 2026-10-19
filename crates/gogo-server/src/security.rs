//! Request checks and security headers (spec section 11.3).
//!
//! * `Host` must be on the allow-list (blocks DNS rebinding).
//! * State-changing methods need a same-origin `Origin` header (plus the
//!   per-session CSRF token, checked in the session extractor).
//! * Every response gets a strict Content Security Policy and related headers.

use crate::config::Config;
use crate::state::Shared;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};

/// Whether a request arrived over HTTPS (set per listener).
#[derive(Clone, Copy, Debug)]
pub struct Scheme {
    pub https: bool,
}

/// The client address used for rate limits and the audit log.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn host_only(host: &str) -> String {
    let h = host.trim().to_ascii_lowercase();
    if h.starts_with('[') {
        return h.split(']').next().map(|s| format!("{s}]")).unwrap_or(h);
    }
    h.rsplit_once(':')
        .map(|(a, p)| if p.chars().all(|c| c.is_ascii_digit()) { a.to_string() } else { h.clone() })
        .unwrap_or(h)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({ "error": message, "code": code });
    (status, axum::Json(body)).into_response()
}

/// Whether the browser is using HTTPS: a TLS listener, or a trusted reverse
/// proxy that says so (`X-Forwarded-Proto`) or whose public address is HTTPS.
pub fn is_https(scheme: Scheme, headers: &HeaderMap, cfg: &Config) -> bool {
    if scheme.https {
        return true;
    }
    if !cfg.trust_proxy {
        return false;
    }
    match headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) {
        Some(v) => v.eq_ignore_ascii_case("https"),
        None => cfg.public_url.as_deref().map(|u| u.starts_with("https://")).unwrap_or(false),
    }
}

/// Origins allowed to send state-changing requests: this site as the browser
/// sees it, plus the configured public address.
fn origin_allowed(origin: &str, expected: &str, cfg: &Config) -> bool {
    if origin.is_empty() {
        return false;
    }
    if origin.eq_ignore_ascii_case(expected) {
        return true;
    }
    cfg.public_url.as_deref().map(|u| origin_of(u).eq_ignore_ascii_case(origin)).unwrap_or(false)
}

fn origin_of(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{}", rest.split('/').next().unwrap_or("")),
        None => url.to_string(),
    }
}

/// Main security middleware.
pub async fn guard(State(state): State<Shared>, mut req: Request<Body>, next: Next) -> Response {
    let headers = req.headers().clone();
    let scheme = req.extensions().get::<Scheme>().copied().unwrap_or(Scheme { https: false });

    // Client address (optionally from a trusted reverse proxy on this machine/LAN).
    let peer =
        req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip()).unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let mut ip = peer;
    if state.cfg.trust_proxy {
        if let Some(fwd) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = fwd.split(',').map(str::trim).rfind(|s| !s.is_empty()) {
                if let Ok(a) = last.parse() {
                    ip = a;
                }
            }
        }
    }
    req.extensions_mut().insert(ClientIp(ip));

    // 1. Host allow-list.
    let host = match headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        Some(h) => h.to_string(),
        None => return error(StatusCode::BAD_REQUEST, "bad_host", "missing Host header"),
    };
    let host_name = host_only(&host);
    if !state.cfg.allowed_hosts.contains(&host_name) {
        tracing::warn!(%host, %ip, "request refused: host not allowed");
        return error(
            StatusCode::MISDIRECTED_REQUEST,
            "bad_host",
            "this address isn't allowed; add it to GOGO_ALLOWED_HOSTS or GOGO_PUBLIC_URL",
        );
    }

    // 2. Same-origin check for state-changing requests.
    let method = req.method().clone();
    let safe = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe {
        let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()).unwrap_or("");
        let https = is_https(scheme, &headers, &state.cfg);
        let expected = format!("{}://{}", if https { "https" } else { "http" }, host.to_ascii_lowercase());
        if !origin_allowed(origin, &expected, &state.cfg) {
            tracing::warn!(%origin, %expected, %ip, "request refused: cross-origin or missing Origin");
            return error(StatusCode::FORBIDDEN, "bad_origin", "request refused: it didn't come from this site");
        }
    }
    if method == Method::OPTIONS {
        return StatusCode::NO_CONTENT.into_response();
    }

    let is_api = req.uri().path().starts_with("/api/");
    let https = is_https(scheme, &headers, &state.cfg);
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"));
    if https {
        h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    }
    if is_api {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::host_only;

    #[test]
    fn hosts() {
        assert_eq!(host_only("127.0.0.1:4680"), "127.0.0.1");
        assert_eq!(host_only("Search.Example.LAN"), "search.example.lan");
        assert_eq!(host_only("[::1]:4680"), "[::1]");
        assert_eq!(host_only("evil.com:80"), "evil.com");
    }
}
