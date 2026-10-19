//! In-process tests of the HTTP layer (spec section 16 security tests).

use crate::config::Config;
use crate::server::app;
use crate::state::{AppState, Shared};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use tower::ServiceExt;

const PW: &str = "correct horse battery";
const HOST: &str = "127.0.0.1:4680";
const ORIGIN: &str = "http://127.0.0.1:4680";

struct T {
    state: Shared,
    _dir: tempfile::TempDir,
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    json: Value,
}

impl T {
    fn new(extra: &[(&str, &str)]) -> T {
        let dir = tempfile::tempdir().unwrap();
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("GOGO_MODE".into(), "standalone".into());
        env.insert("GOGO_DATA_DIR".into(), dir.path().join("data").to_string_lossy().into());
        for (k, v) in extra {
            env.insert(k.to_string(), v.to_string());
        }
        let cfg = Config::from_map(&env).unwrap();
        cfg.startup_checks().unwrap();
        T { state: AppState::new(cfg).unwrap(), _dir: dir }
    }

    #[allow(clippy::too_many_arguments)]
    async fn req(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        cookie: Option<&str>,
        csrf: Option<&str>,
        origin: Option<&str>,
        host: &str,
    ) -> Resp {
        let mut b = Request::builder().method(method).uri(path).header("host", host);
        if let Some(o) = origin {
            b = b.header("origin", o);
        }
        if let Some(c) = cookie {
            b = b.header("cookie", c);
        }
        if let Some(c) = csrf {
            b = b.header("x-csrf-token", c);
        }
        let req = match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = app(self.state.clone(), false).oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Resp { status, headers, json }
    }

    async fn get(&self, path: &str, s: Option<&Sess>) -> Resp {
        self.req("GET", path, None, s.map(|s| s.cookie.as_str()), None, None, HOST).await
    }

    async fn post(&self, path: &str, body: Value, s: Option<&Sess>) -> Resp {
        self.req("POST", path, Some(body), s.map(|s| s.cookie.as_str()), s.map(|s| s.csrf.as_str()), Some(ORIGIN), HOST)
            .await
    }

    async fn send(&self, method: &str, path: &str, body: Value, s: &Sess) -> Resp {
        self.req(method, path, Some(body), Some(&s.cookie), Some(&s.csrf), Some(ORIGIN), HOST).await
    }

    async fn login(&self, user: &str, pw: &str) -> Sess {
        let r = self.post("/api/v1/auth/login", json!({ "username": user, "password": pw }), None).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
        sess(&r)
    }
}

struct Sess {
    cookie: String,
    csrf: String,
}

fn sess(r: &Resp) -> Sess {
    let set = r.headers.get("set-cookie").unwrap().to_str().unwrap();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict"));
    Sess { cookie: set.split(';').next().unwrap().to_string(), csrf: r.json["csrf"].as_str().unwrap().to_string() }
}

#[tokio::test]
async fn security_headers_and_host_check() {
    let t = T::new(&[]);
    let r = t.get("/api/health", None).await;
    assert_eq!(r.status, StatusCode::OK);
    let csp = r.headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(
        csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'") && !csp.contains("unsafe-inline")
    );
    assert_eq!(r.headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(r.headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(r.headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    // DNS rebinding: an attacker's host name pointing at 127.0.0.1 is refused.
    let r = t.req("GET", "/api/health", None, None, None, None, "evil.example:4680").await;
    assert_eq!(r.status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn setup_then_sign_in_and_csrf() {
    let t = T::new(&[]);
    let b = t.get("/api/v1/bootstrap", None).await;
    assert_eq!(b.json["setup_required"], true);
    // Wrong setup code
    let r =
        t.post("/api/v1/setup", json!({ "code": "AAAA-BBBB-CCCC", "username": "admin", "password": PW }), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Use the real code (tests read it from state by replacing it with a known one).
    let code = "TEST-CODE-0001";
    t.state.setup.lock().as_mut().unwrap().code_hash =
        gogo_auth::sha256_hex(gogo_auth::normalize_code(code).as_bytes());
    let r = t.post("/api/v1/setup", json!({ "code": code, "username": "admin", "password": PW }), None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    assert_eq!(t.get("/api/v1/bootstrap", None).await.json["setup_required"], false);
    let r = t.post("/api/v1/setup", json!({ "code": code, "username": "x2", "password": PW }), None).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "setup only once");

    let s = t.login("admin", PW).await;
    assert_eq!(t.get("/api/v1/me", Some(&s)).await.json["user"]["role"], "admin");
    assert_eq!(t.get("/api/v1/me", None).await.status, StatusCode::UNAUTHORIZED);

    // State change without CSRF token -> refused
    let r = t
        .req(
            "POST",
            "/api/v1/users",
            Some(json!({"username":"bob","password":PW,"role":"user"})),
            Some(&s.cookie),
            None,
            Some(ORIGIN),
            HOST,
        )
        .await;
    assert_eq!(r.json["code"], "bad_csrf");
    // Cross-origin -> refused even with the token
    let r = t
        .req(
            "POST",
            "/api/v1/users",
            Some(json!({"username":"bob","password":PW,"role":"user"})),
            Some(&s.cookie),
            Some(&s.csrf),
            Some("http://evil.example"),
            HOST,
        )
        .await;
    assert_eq!(r.json["code"], "bad_origin");
    // Missing Origin -> refused
    let r = t
        .req(
            "POST",
            "/api/v1/users",
            Some(json!({"username":"bob","password":PW,"role":"user"})),
            Some(&s.cookie),
            Some(&s.csrf),
            None,
            HOST,
        )
        .await;
    assert_eq!(r.json["code"], "bad_origin");
    // Proper request
    let r = t.post("/api/v1/users", json!({"username":"bob","password":PW,"role":"user"}), Some(&s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);

    // Logout ends the session
    t.post("/api/v1/auth/logout", json!({}), Some(&s)).await;
    assert_eq!(t.get("/api/v1/me", Some(&s)).await.status, StatusCode::UNAUTHORIZED);
}

async fn with_admin(t: &T) -> Sess {
    t.state.store.create_local_user("admin", PW, gogo_auth::Role::Admin).unwrap();
    t.state.ensure_setup_code().unwrap();
    t.login("admin", PW).await
}

#[tokio::test]
async fn users_cannot_reach_admin_routes_and_reauth_expires() {
    let t = T::new(&[]);
    let a = with_admin(&t).await;
    t.state.store.create_local_user("bob", PW, gogo_auth::Role::User).unwrap();
    let b = t.login("bob", PW).await;
    for path in ["/api/v1/users", "/api/v1/libraries", "/api/v1/audit"] {
        assert_eq!(t.get(path, Some(&b)).await.status, StatusCode::FORBIDDEN, "{path}");
    }
    let bob_id = t.state.store.user_by_name("bob").unwrap().unwrap().id;
    // Fresh sign-in counts as recent; age the session to require "confirm it's you".
    t.state.store.age_reauth_for_tests(a.cookie.split('=').nth(1).unwrap(), 3600);
    let r = t.send("DELETE", &format!("/api/v1/users/{bob_id}"), json!({}), &a).await;
    assert_eq!(r.json["code"], "reauth_required");
    let r = t.post("/api/v1/auth/reauth", json!({ "password": PW }), Some(&a)).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t.send("DELETE", &format!("/api/v1/users/{bob_id}"), json!({}), &a).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    // The deleted user's session no longer works.
    assert_eq!(t.get("/api/v1/me", Some(&b)).await.status, StatusCode::UNAUTHORIZED);
    // Last administrator protection over HTTP.
    let me = t.get("/api/v1/me", Some(&a)).await.json["user"]["id"].as_i64().unwrap();
    let r = t.send("PATCH", &format!("/api/v1/users/{me}"), json!({ "role": "user" }), &a).await;
    assert_eq!(r.json["code"], "last_admin");
}

#[tokio::test]
async fn login_rate_limit_and_lockout() {
    let t = T::new(&[]);
    with_admin(&t).await;
    let mut statuses = Vec::new();
    for _ in 0..12 {
        statuses.push(
            t.post("/api/v1/auth/login", json!({ "username": "admin", "password": "wrong password!!" }), None)
                .await
                .status,
        );
    }
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS));
    let audit = t.state.audit.tail(100, Some("auth.signin_failed")).unwrap();
    assert!(audit.len() >= 5);
}

#[tokio::test]
async fn search_respects_library_permissions() {
    let t = T::new(&[]);
    let a = with_admin(&t).await;
    let files = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(files.path().join("plans")).unwrap();
    std::fs::write(files.path().join("plans/site-plan-2026.dwg"), b"x").unwrap();
    std::fs::write(files.path().join("budget.xlsx"), b"x").unwrap();
    let r = t.post("/api/v1/libraries", json!({ "name": "Projects", "path": files.path().to_string_lossy(), "display_prefix": "\\\\NAS\\Projects" }), Some(&a)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    let lib_id = r.json["library"]["id"].as_i64().unwrap();
    // Wait until the first full listing is done (on Windows the NTFS file table
    // of the whole volume is read, which can take a while on CI runners).
    let mut status = Value::Null;
    for _ in 0..1200 {
        status = t.get("/api/v1/status", Some(&a)).await.json;
        let lib = &status["libraries"][0];
        if lib["state"] == "watching" && lib["entries"].as_u64().unwrap_or(0) >= 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    println!("library status: {status}");
    let r = t.get("/api/v1/search?q=site%20plan", Some(&a)).await;
    assert_eq!(r.json["hits"][0]["name"], "site-plan-2026.dwg", "{:?}", r.json);
    assert_eq!(r.json["hits"][0]["path"], "\\\\NAS\\Projects\\plans\\site-plan-2026.dwg");

    t.state.store.create_local_user("bob", PW, gogo_auth::Role::User).unwrap();
    let b = t.login("bob", PW).await;
    let r = t.get("/api/v1/search?q=site", Some(&b)).await;
    assert_eq!(r.json["total"], 0, "new libraries are admin-only");
    let r =
        t.send("PUT", &format!("/api/v1/libraries/{lib_id}/access"), json!({ "principals": ["role:user"] }), &a).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t.get("/api/v1/search?q=ext:xlsx", Some(&b)).await;
    assert_eq!(r.json["hits"][0]["name"], "budget.xlsx");
    // Bad query gives a clear error.
    let long = "a".repeat(600);
    assert_eq!(t.get(&format!("/api/v1/search?q={long}"), Some(&b)).await.status, StatusCode::BAD_REQUEST);
    // A library can't be the data folder.
    let data = t.state.cfg.data_dir.to_string_lossy().to_string();
    let r = t.post("/api/v1/libraries", json!({ "name": "Data", "path": data }), Some(&a)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_totp_enforced_when_network_reachable() {
    let t = T::new(&[
        ("GOGO_HTTP_BIND", "0.0.0.0:4680"),
        ("GOGO_TRUST_PROXY", "true"),
        ("GOGO_ALLOWED_HOSTS", "127.0.0.1"),
    ]);
    let code = "TEST-CODE-0002";
    t.state.setup.lock().as_mut().unwrap().code_hash =
        gogo_auth::sha256_hex(gogo_auth::normalize_code(code).as_bytes());
    // Setup without a second factor is refused.
    let r = t.post("/api/v1/setup", json!({ "code": code, "username": "admin", "password": PW }), None).await;
    assert_eq!(r.json["code"], "code_required");
    let r = t.post("/api/v1/setup/totp", json!({ "code": code, "username": "admin" }), None).await;
    let secret = r.json["secret"].as_str().unwrap().to_string();
    assert!(r.json["qr"].as_str().unwrap().starts_with("data:image/svg+xml;base64,"));
    let otp = gogo_auth::totp::code_at(&secret, gogo_auth::now() / gogo_auth::totp::PERIOD).unwrap();
    let r = t
        .post("/api/v1/setup", json!({ "code": code, "username": "admin", "password": PW, "totp_code": otp }), None)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    // A second admin created without 2FA is held at the setup screen.
    t.state.store.create_local_user("admin2", PW, gogo_auth::Role::Admin).unwrap();
    let s = t.login("admin2", PW).await;
    assert_eq!(t.get("/api/v1/users", Some(&s)).await.json["code"], "totp_setup_required");
    assert_eq!(t.get("/api/v1/me", Some(&s)).await.json["totp_setup_required"], true);
}

#[tokio::test]
async fn static_files_and_traversal() {
    let t = T::new(&[]);
    // Traversal never reaches the file system: it gets the app page.
    let r = t.get("/assets/../../../etc/passwd", None).await;
    assert!(
        r.status == StatusCode::NOT_FOUND
            || r.headers.get("content-type").unwrap().to_str().unwrap().starts_with("text/html")
    );
    let r = t.get("/api/v1/nope", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.get("/missing.js", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn recover_with_reset_code() {
    let t = T::new(&[]);
    with_admin(&t).await;
    let code = t.state.store.create_reset_code().unwrap();
    let r = t
        .post(
            "/api/v1/auth/recover",
            json!({ "code": code, "username": "admin", "password": "a whole new passphrase" }),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    t.login("admin", "a whole new passphrase").await;
    assert!(!t.state.audit.tail(10, Some("admin.recovered")).unwrap().is_empty());
}

#[tokio::test]
async fn behind_reverse_proxy() {
    let t = T::new(&[
        ("GOGO_HTTP_BIND", "0.0.0.0:4680"),
        ("GOGO_TRUST_PROXY", "true"),
        ("GOGO_PUBLIC_URL", "https://search.example.com"),
    ]);
    t.state.store.create_local_user("bob", PW, gogo_auth::Role::User).unwrap();
    let body = json!({ "username": "bob", "password": PW });
    let r = t
        .req(
            "POST",
            "/api/v1/auth/login",
            Some(body.clone()),
            None,
            None,
            Some("https://search.example.com"),
            "search.example.com",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    let cookie = r.headers.get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.starts_with("__Host-gogo_session=") && cookie.contains("Secure"), "{cookie}");
    assert!(r.headers.get("strict-transport-security").is_some());
    let r = t
        .req(
            "POST",
            "/api/v1/auth/login",
            Some(body),
            None,
            None,
            Some("https://evil.example.com"),
            "search.example.com",
        )
        .await;
    assert_eq!(r.json["code"], "bad_origin");
}
