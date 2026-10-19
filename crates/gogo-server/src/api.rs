//! JSON API under `/api/v1` (spec section 9.4).
//!
//! Rules: every `GET` is read-only; every state change needs a signed-in
//! session plus its CSRF token in the `X-CSRF-Token` header (and passes the
//! same-origin check in `security.rs`). Risky actions also need a fresh
//! "confirm it's you" (re-authentication within the last 5 minutes).

use crate::config::{LocalAccounts, Mode};
use crate::security::{is_https, ClientIp, Scheme};
use crate::state::Shared;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use gogo_auth::{
    ct_eq, normalize_code, now, sha256_hex, totp, AccountKind, AuthError, Role, Session, StoreError, User,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

/// How long a "confirm it's you" stays valid.
const REAUTH_SECS: i64 = 5 * 60;

// ---------- errors ----------

pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    extra: Option<Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError { status, code, message: message.into(), extra: None }
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid", message)
    }
    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "not found")
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.message, "code": self.code });
        if let (Some(extra), Some(obj)) = (self.extra, body.as_object_mut()) {
            if let Some(e) = extra.as_object() {
                for (k, v) in e {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }
        (self.status, Json(body)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => ApiError::not_found(),
            StoreError::LastAdmin => ApiError::new(StatusCode::CONFLICT, "last_admin", e.to_string()),
            StoreError::Duplicate => ApiError::new(StatusCode::CONFLICT, "duplicate", e.to_string()),
            StoreError::Invalid(m) => ApiError::bad(m),
            StoreError::Password(p) => ApiError::new(StatusCode::BAD_REQUEST, "weak_password", p.to_string()),
            StoreError::Db(err) => {
                tracing::error!("database error: {err}");
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
            }
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        let msg = e.to_string();
        match e {
            AuthError::InvalidCredentials => ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", msg),
            AuthError::Locked { until } => ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "locked",
                message: msg,
                extra: Some(json!({ "locked_until": until })),
            },
            AuthError::CodeRequired => ApiError::new(StatusCode::UNAUTHORIZED, "code_required", msg),
            AuthError::BadCode => ApiError::new(StatusCode::UNAUTHORIZED, "bad_code", msg),
            AuthError::NotAllowed => ApiError::new(StatusCode::FORBIDDEN, "not_allowed", msg),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("internal error: {e:#}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
    }
}

type ApiResult<T> = Result<T, ApiError>;

// ---------- sessions ----------

pub fn cookie_name(https: bool) -> &'static str {
    if https {
        "__Host-gogo_session"
    } else {
        "gogo_session"
    }
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for v in headers.get_all(header::COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, val)) = part.trim().split_once('=') {
                if k == name {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn session_cookie(token: &str, https: bool, max_age: i64) -> HeaderValue {
    let secure = if https { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
        cookie_name(https)
    ))
    .expect("cookie header")
}

fn clear_cookie(https: bool) -> HeaderValue {
    session_cookie("", https, 0)
}

/// A signed-in request.
pub struct Auth {
    pub user: User,
    pub session: Session,
    pub token: String,
    pub ip: String,
}

/// Paths an administrator may use before setting up the required second factor.
const TOTP_SETUP_PATHS: &[&str] =
    &["/api/v1/me", "/api/v1/me/totp/begin", "/api/v1/me/totp/confirm", "/api/v1/auth/logout", "/api/v1/auth/reauth"];

impl FromRequestParts<Shared> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, Self::Rejection> {
        let scheme = parts.extensions.get::<Scheme>().copied().unwrap_or(Scheme { https: false });
        let https = is_https(scheme, &parts.headers, &state.cfg);
        let unauth = || ApiError::new(StatusCode::UNAUTHORIZED, "signed_out", "please sign in");
        let token = read_cookie(&parts.headers, cookie_name(https)).ok_or_else(unauth)?;
        let (session, user) = state.store.session(&token, state.session_policy())?.ok_or_else(unauth)?;
        let safe = matches!(parts.method, Method::GET | Method::HEAD);
        if !safe {
            let sent = parts.headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or("");
            if !ct_eq(sent, &session.csrf) {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "bad_csrf",
                    "request refused: missing or wrong CSRF token",
                ));
            }
        }
        if needs_totp_setup(state, &user) && !TOTP_SETUP_PATHS.contains(&parts.uri.path()) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "totp_setup_required",
                "administrators must set up a sign-in code app before continuing",
            ));
        }
        let ip = parts.extensions.get::<ClientIp>().map(|c| c.0.to_string()).unwrap_or_default();
        Ok(Auth { user, session, token, ip })
    }
}

fn needs_totp_setup(state: &Shared, user: &User) -> bool {
    state.cfg.require_totp_for_local_admins
        && user.kind == AccountKind::Local
        && user.role == Role::Admin
        && !user.totp_enabled
}

/// A signed-in administrator.
pub struct Admin(pub Auth);

impl FromRequestParts<Shared> for Admin {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, Self::Rejection> {
        let a = Auth::from_request_parts(parts, state).await?;
        if a.user.role != Role::Admin {
            return Err(ApiError::forbidden("administrators only"));
        }
        Ok(Admin(a))
    }
}

fn require_recent(a: &Auth) -> ApiResult<()> {
    if now() - a.session.reauth_at <= REAUTH_SECS {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::FORBIDDEN, "reauth_required", "confirm it's you first"))
    }
}

fn client_ip(parts_ip: Option<&ClientIp>) -> std::net::IpAddr {
    parts_ip.map(|c| c.0).unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]))
}

struct Ctx {
    ip: std::net::IpAddr,
    https: bool,
}

impl FromRequestParts<Shared> for Ctx {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, Self::Rejection> {
        let scheme = parts.extensions.get::<Scheme>().copied().unwrap_or(Scheme { https: false });
        Ok(Ctx {
            ip: client_ip(parts.extensions.get::<ClientIp>()),
            https: is_https(scheme, &parts.headers, &state.cfg),
        })
    }
}

fn audit(state: &Shared, event: &str, actor: Option<&str>, ip: &str, details: Value) {
    state.audit.record(event, actor, (!ip.is_empty()).then_some(ip), details);
}

// ---------- router ----------

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/v1/bootstrap", get(bootstrap))
        .route("/api/v1/setup/totp", post(setup_totp))
        .route("/api/v1/setup", post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/onetime", post(onetime))
        .route("/api/v1/auth/reauth", post(reauth))
        .route("/api/v1/auth/recover", post(recover))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/password", post(change_password))
        .route("/api/v1/me/totp/begin", post(totp_begin))
        .route("/api/v1/me/totp/confirm", post(totp_confirm))
        .route("/api/v1/me/totp/disable", post(totp_disable))
        .route("/api/v1/me/sessions", get(my_sessions))
        .route("/api/v1/me/sessions/end-others", post(end_other_sessions))
        .route("/api/v1/search", get(search))
        .route("/api/v1/status", get(status))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{id}", patch(update_user).delete(delete_user))
        .route("/api/v1/users/{id}/password", post(admin_set_password))
        .route("/api/v1/users/{id}/unlock", post(unlock_user))
        .route("/api/v1/users/{id}/sessions/end", post(end_user_sessions))
        .route("/api/v1/libraries", get(list_libraries).post(add_library))
        .route("/api/v1/libraries/{id}", patch(update_library).delete(remove_library))
        .route("/api/v1/libraries/{id}/access", put(set_library_access))
        .route("/api/v1/libraries/{id}/recheck", post(recheck_library))
        .route("/api/v1/audit", get(audit_tail))
}

// ---------- public ----------

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn bootstrap(State(s): State<Shared>) -> Json<Value> {
    Json(json!({
        "product": "Gogo Desktop",
        "version": env!("CARGO_PKG_VERSION"),
        "setup_required": s.setup_required(),
        "local_accounts": s.cfg.local_accounts,
        "sso_enabled": false,
        "same_pc_signin": cfg!(windows) && s.cfg.http_bind.map(|a| a.ip().is_loopback()).unwrap_or(false),
        "require_totp_for_admins": s.cfg.require_totp_for_local_admins,
    }))
}

fn qr_data_url(text: &str) -> Option<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(true).build();
    Some(format!("data:image/svg+xml;base64,{}", data_encoding::BASE64.encode(svg.as_bytes())))
}

fn totp_payload(secret: &str, account: &str) -> Value {
    let url = totp::otpauth_url(secret, account, "Gogo Desktop");
    json!({ "secret": secret, "otpauth_url": url, "qr": qr_data_url(&url) })
}

fn check_setup_code(s: &Shared, code: &str) -> ApiResult<()> {
    let guard = s.setup.lock();
    let setup =
        guard.as_ref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "setup_done", "setup is already complete"))?;
    if !ct_eq(&sha256_hex(normalize_code(code).as_bytes()), &setup.code_hash) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "bad_setup_code",
            "wrong setup code; check the program log",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct SetupTotpReq {
    code: String,
    username: String,
}

async fn setup_totp(State(s): State<Shared>, ctx: Ctx, Json(r): Json<SetupTotpReq>) -> ApiResult<Json<Value>> {
    if !s.rate.allow("setup", ctx.ip, 10, 60) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute"));
    }
    check_setup_code(&s, &r.code)?;
    let secret = totp::new_secret();
    if let Some(st) = s.setup.lock().as_mut() {
        st.totp_secret = Some(secret.clone());
    }
    Ok(Json(totp_payload(&secret, &r.username)))
}

#[derive(Deserialize)]
struct SetupReq {
    code: String,
    username: String,
    password: String,
    totp_code: Option<String>,
}

async fn setup(State(s): State<Shared>, ctx: Ctx, Json(r): Json<SetupReq>) -> ApiResult<Response> {
    if !s.rate.allow("setup", ctx.ip, 10, 60) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute"));
    }
    check_setup_code(&s, &r.code)?;
    let secret = s.setup.lock().as_ref().and_then(|st| st.totp_secret.clone());
    if s.cfg.require_totp_for_local_admins {
        let (Some(secret), Some(code)) = (&secret, &r.totp_code) else {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "code_required", "set up the sign-in code app first"));
        };
        if totp::verify(secret, code, now(), 0).is_none() {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "bad_code", "wrong or expired code"));
        }
    }
    let user = s.store.create_local_user(r.username.trim(), &r.password, Role::Admin)?;
    if let (Some(secret), Some(code)) = (&secret, &r.totp_code) {
        if !code.trim().is_empty() {
            s.store.totp_enable_with(user.id, secret, code)?;
        }
    }
    s.finish_setup();
    audit(&s, "setup.completed", Some(&user.username), &ctx.ip.to_string(), json!({ "admin": user.username }));
    tracing::info!(admin = %user.username, "setup complete");
    let user = s.store.user(user.id)?;
    sign_in_response(&s, &user, "setup", &ctx)
}

fn sign_in_response(s: &Shared, user: &User, method: &str, ctx: &Ctx) -> ApiResult<Response> {
    let (token, session) = s.store.create_session(user.id, method, &ctx.ip.to_string(), s.session_policy())?;
    let mut resp = Json(json!({ "user": user, "csrf": session.csrf })).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, session_cookie(&token, ctx.https, s.session_policy().absolute_secs));
    Ok(resp)
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
    code: Option<String>,
}

async fn login(State(s): State<Shared>, ctx: Ctx, Json(r): Json<LoginReq>) -> ApiResult<Response> {
    if !s.rate.allow("login", ctx.ip, 10, 60) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many sign-in attempts; wait a minute",
        ));
    }
    if r.username.len() > 128 || r.password.len() > 1024 {
        return Err(AuthError::InvalidCredentials.into());
    }
    let admins_only = s.cfg.local_accounts == LocalAccounts::AdminsOnly;
    let store = s.clone();
    let (u, p, c) = (r.username.trim().to_string(), r.password.clone(), r.code.clone());
    let result = tokio::task::spawn_blocking(move || store.store.authenticate_local(&u, &p, c.as_deref(), admins_only))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    match result {
        Ok(user) => {
            audit(&s, "auth.signin", Some(&user.username), &ctx.ip.to_string(), json!({ "method": "password" }));
            sign_in_response(&s, &user, "password", &ctx)
        }
        Err(e) => {
            if e != AuthError::CodeRequired {
                audit(
                    &s,
                    "auth.signin_failed",
                    Some(r.username.trim()),
                    &ctx.ip.to_string(),
                    json!({ "reason": format!("{e:?}").split_whitespace().next().unwrap_or("").to_string() }),
                );
            }
            Err(e.into())
        }
    }
}

async fn logout(State(s): State<Shared>, ctx: Ctx, a: Auth) -> ApiResult<Response> {
    s.store.delete_session(&a.token)?;
    audit(&s, "auth.signout", Some(&a.user.username), &a.ip, json!({}));
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, clear_cookie(ctx.https));
    Ok(resp)
}

#[derive(Deserialize)]
struct OnetimeReq {
    token: String,
}

async fn onetime(State(s): State<Shared>, ctx: Ctx, Json(r): Json<OnetimeReq>) -> ApiResult<Response> {
    if !s.rate.allow("onetime", ctx.ip, 20, 60) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute"));
    }
    if !ctx.ip.is_loopback() {
        return Err(ApiError::forbidden("same-PC sign-in only works on this PC"));
    }
    let uid = s
        .take_onetime(r.token.trim())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "bad_token", "this sign-in link is used or expired"))?;
    let user = s.store.user(uid)?;
    if user.disabled {
        return Err(AuthError::InvalidCredentials.into());
    }
    audit(&s, "auth.signin", Some(&user.username), &ctx.ip.to_string(), json!({ "method": "windows" }));
    sign_in_response(&s, &user, "windows", &ctx)
}

#[derive(Deserialize)]
struct ReauthReq {
    password: String,
    code: Option<String>,
}

async fn reauth(State(s): State<Shared>, a: Auth, Json(r): Json<ReauthReq>) -> ApiResult<Json<Value>> {
    if a.user.kind != AccountKind::Local {
        return Err(ApiError::bad("Windows accounts confirm by signing in again with 'gogo signin'"));
    }
    let ip: std::net::IpAddr = a.ip.parse().unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
    if !s.rate.allow("reauth", ip, 10, 60) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute"));
    }
    let store = s.clone();
    let (id, pw, code) = (a.user.id, r.password.clone(), r.code.clone());
    tokio::task::spawn_blocking(move || store.store.verify_local(id, &pw, code.as_deref()))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    s.store.mark_reauth(&a.token)?;
    audit(&s, "auth.reauth", Some(&a.user.username), &a.ip, json!({}));
    Ok(Json(json!({ "ok": true, "valid_for_secs": REAUTH_SECS })))
}

#[derive(Deserialize)]
struct RecoverReq {
    code: String,
    username: String,
    password: String,
}

/// Emergency administrator recovery with a code from `gogo admin reset`.
async fn recover(State(s): State<Shared>, ctx: Ctx, Json(r): Json<RecoverReq>) -> ApiResult<Json<Value>> {
    if !s.rate.allow("recover", ctx.ip, 5, 60) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute"));
    }
    let store = s.clone();
    let (code, user, pw) = (r.code.clone(), r.username.trim().to_string(), r.password.clone());
    let res = tokio::task::spawn_blocking(move || store.store.use_reset_code(&code, &user, &pw))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    match res {
        Ok(u) => {
            audit(&s, "admin.recovered", Some(&u.username), &ctx.ip.to_string(), json!({ "user": u.username }));
            Ok(Json(json!({ "ok": true })))
        }
        Err(e) => {
            audit(&s, "admin.recover_failed", Some(r.username.trim()), &ctx.ip.to_string(), json!({}));
            Err(e.into())
        }
    }
}

// ---------- me ----------

async fn me(State(s): State<Shared>, a: Auth) -> ApiResult<Json<Value>> {
    let libs = s.store.list_libraries()?;
    let allowed = s.store.libraries_for(&a.user)?;
    let libraries: Vec<Value> =
        libs.iter().filter(|l| allowed.contains(&l.id)).map(|l| json!({ "id": l.id, "name": l.name })).collect();
    Ok(Json(json!({
        "user": a.user,
        "csrf": a.session.csrf,
        "libraries": libraries,
        "reauth_valid_for": (REAUTH_SECS - (now() - a.session.reauth_at)).max(0),
        "totp_setup_required": needs_totp_setup(&s, &a.user),
        "session": { "method": a.session.method, "created_at": a.session.created_at, "expires_at": a.session.expires_at },
        "locked_settings": s.cfg.locked,
        "mode": s.cfg.mode,
    })))
}

#[derive(Deserialize)]
struct PasswordReq {
    current: String,
    new: String,
    code: Option<String>,
}

async fn change_password(State(s): State<Shared>, a: Auth, Json(r): Json<PasswordReq>) -> ApiResult<Json<Value>> {
    let store = s.clone();
    let (id, cur, code) = (a.user.id, r.current.clone(), r.code.clone());
    tokio::task::spawn_blocking(move || store.store.verify_local(id, &cur, code.as_deref()))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    s.store.set_password(a.user.id, &r.new, Some(&a.token))?;
    audit(&s, "user.password_changed", Some(&a.user.username), &a.ip, json!({ "user": a.user.username, "by": "self" }));
    Ok(Json(json!({ "ok": true })))
}

async fn totp_begin(State(s): State<Shared>, a: Auth) -> ApiResult<Json<Value>> {
    if a.user.kind != AccountKind::Local {
        return Err(ApiError::bad("only Gogo Desktop accounts use sign-in codes"));
    }
    if !needs_totp_setup(&s, &a.user) {
        require_recent(&a)?;
    }
    let secret = s.store.totp_begin(a.user.id)?;
    Ok(Json(totp_payload(&secret, &a.user.username)))
}

#[derive(Deserialize)]
struct CodeReq {
    code: String,
}

async fn totp_confirm(State(s): State<Shared>, a: Auth, Json(r): Json<CodeReq>) -> ApiResult<Json<Value>> {
    s.store.totp_confirm(a.user.id, &r.code)?;
    audit(&s, "user.totp_enabled", Some(&a.user.username), &a.ip, json!({ "user": a.user.username }));
    Ok(Json(json!({ "ok": true })))
}

async fn totp_disable(State(s): State<Shared>, a: Auth) -> ApiResult<Json<Value>> {
    require_recent(&a)?;
    if s.cfg.require_totp_for_local_admins && a.user.role == Role::Admin {
        return Err(ApiError::forbidden("administrators must keep a sign-in code app on this server"));
    }
    s.store.totp_disable(a.user.id)?;
    audit(&s, "user.totp_disabled", Some(&a.user.username), &a.ip, json!({ "user": a.user.username }));
    Ok(Json(json!({ "ok": true })))
}

async fn my_sessions(State(s): State<Shared>, a: Auth) -> ApiResult<Json<Value>> {
    let sessions = s.store.list_sessions(a.user.id)?;
    let list: Vec<Value> = sessions
        .iter()
        .map(|x| {
            json!({
                "current": x.id_hash == a.session.id_hash,
                "method": x.method, "ip": x.ip,
                "created_at": x.created_at, "last_seen": x.last_seen, "expires_at": x.expires_at,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": list })))
}

async fn end_other_sessions(State(s): State<Shared>, a: Auth) -> ApiResult<Json<Value>> {
    let ended = s.store.delete_user_sessions_except(a.user.id, &a.token)?;
    audit(&s, "user.sessions_ended", Some(&a.user.username), &a.ip, json!({ "user": a.user.username, "count": ended }));
    Ok(Json(json!({ "ended": ended })))
}

// ---------- search ----------

#[derive(Deserialize)]
struct SearchParams {
    q: String,
    limit: Option<usize>,
    /// Restrict to one library by name (names may contain spaces).
    lib: Option<String>,
}

async fn search(State(s): State<Shared>, a: Auth, Query(p): Query<SearchParams>) -> ApiResult<Json<Value>> {
    let started = std::time::Instant::now();
    let query = gogo_index::parse_query(&p.q, now())
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "bad_query", e.to_string()))?;
    let libs = s.store.list_libraries()?;
    let mut allowed = s.store.libraries_for(&a.user)?;
    if !query.libraries.is_empty() {
        allowed.retain(|id| {
            libs.iter().any(|l| l.id == *id && query.libraries.iter().any(|n| n.eq_ignore_ascii_case(&l.name)))
        });
    }
    if let Some(name) = p.lib.as_deref().filter(|n| !n.is_empty()) {
        allowed.retain(|id| libs.iter().any(|l| l.id == *id && l.name.eq_ignore_ascii_case(name)));
    }
    let allowed16: Vec<u16> = allowed.iter().map(|&i| i as u16).collect();
    let limit = p.limit.unwrap_or(50).clamp(1, 200);
    let st = s.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut r = st.index.read().search(&query, &allowed16, limit);
        // Fill in size/time for hits listed without them (NTFS file table).
        let lib_paths: HashMap<u16, PathBuf> = st
            .store
            .list_libraries()
            .unwrap_or_default()
            .into_iter()
            .map(|l| (l.id as u16, PathBuf::from(l.path)))
            .collect();
        for h in r.hits.iter_mut().filter(|h| h.meta.mtime == 0) {
            if let Some(root) = lib_paths.get(&h.library) {
                let full = h.rel_path.split('/').fold(root.clone(), |p, c| p.join(c));
                if let Ok(m) = std::fs::symlink_metadata(&full) {
                    let mtime = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    h.meta.mtime = mtime;
                    if !m.is_dir() {
                        h.meta.size = m.len();
                    }
                    st.index.write().set_meta(h.library, h.key, h.meta);
                }
            }
        }
        r
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?;
    let by_id: HashMap<i64, &gogo_auth::Library> = libs.iter().map(|l| (l.id, l)).collect();
    let hits: Vec<Value> = result
        .hits
        .iter()
        .filter_map(|h| {
            let lib = by_id.get(&(h.library as i64))?;
            Some(json!({
                "id": format!("{}-{:x}", h.library, h.key),
                "library": lib.name,
                "name": h.name,
                "rel_path": h.rel_path,
                "path": s.display_path(lib, &h.rel_path),
                "folder": s.display_path(lib, h.rel_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("")),
                "is_dir": h.meta.is_dir,
                "size": h.meta.size,
                "mtime": h.meta.mtime,
            }))
        })
        .collect();
    Ok(Json(json!({
        "total": result.total,
        "took_ms": started.elapsed().as_secs_f64() * 1000.0,
        "hits": hits,
    })))
}

async fn status(State(s): State<Shared>, a: Auth) -> ApiResult<Json<Value>> {
    let allowed = s.store.libraries_for(&a.user)?;
    let admin = a.user.role == Role::Admin;
    let libs: Vec<Value> = s
        .library_status()
        .into_iter()
        .filter(|l| allowed.contains(&(l.id as i64)))
        .map(|l| {
            let mut v = serde_json::to_value(&l).unwrap_or(Value::Null);
            if !admin {
                if let Some(o) = v.as_object_mut() {
                    o.remove("message");
                    o.remove("watch_limit");
                    o.remove("watches_needed");
                }
            }
            v
        })
        .collect();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": s.cfg.mode,
        "profile": s.cfg.profile,
        "uptime_secs": s.started.elapsed().as_secs(),
        "libraries": libs,
        "settings": if admin { json!({
            "local_accounts": s.cfg.local_accounts,
            "require_totp_for_local_admins": s.cfg.require_totp_for_local_admins,
            "sso_enabled": s.cfg.sso_enabled,
            "approval": { "mandatory": true, "pending_max": s.cfg.approval_pending_max, "expiry_days": s.cfg.approval_expiry_days },
            "session_idle_hours": s.cfg.session_idle.as_secs() / 3600,
            "session_max_days": s.cfg.session_max.as_secs() / 86_400,
            "locked": s.cfg.locked,
        }) } else { Value::Null },
    })))
}

// ---------- users (admin) ----------

async fn list_users(State(s): State<Shared>, Admin(_): Admin) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "users": s.store.list_users()? })))
}

#[derive(Deserialize)]
struct CreateUserReq {
    username: String,
    password: String,
    role: String,
}

async fn create_user(State(s): State<Shared>, Admin(a): Admin, Json(r): Json<CreateUserReq>) -> ApiResult<Json<Value>> {
    let role = Role::parse(&r.role).ok_or_else(|| ApiError::bad("role must be admin or user"))?;
    if role == Role::Admin {
        require_recent(&a)?;
    }
    let u = s.store.create_local_user(r.username.trim(), &r.password, role)?;
    audit(&s, "user.created", Some(&a.user.username), &a.ip, json!({ "user": u.username, "role": role.as_str() }));
    Ok(Json(json!({ "user": u })))
}

#[derive(Deserialize)]
struct UpdateUserReq {
    role: Option<String>,
    disabled: Option<bool>,
}

async fn update_user(
    State(s): State<Shared>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Json(r): Json<UpdateUserReq>,
) -> ApiResult<Json<Value>> {
    require_recent(&a)?;
    let target = s.store.user(id)?;
    if let Some(role) = &r.role {
        let role = Role::parse(role).ok_or_else(|| ApiError::bad("role must be admin or user"))?;
        s.store.set_role(id, role)?;
        audit(
            &s,
            "user.role_changed",
            Some(&a.user.username),
            &a.ip,
            json!({ "user": target.username, "role": role.as_str() }),
        );
    }
    if let Some(d) = r.disabled {
        if d && id == a.user.id {
            return Err(ApiError::bad("you can't disable your own account"));
        }
        s.store.set_disabled(id, d)?;
        audit(
            &s,
            if d { "user.disabled" } else { "user.enabled" },
            Some(&a.user.username),
            &a.ip,
            json!({ "user": target.username }),
        );
    }
    Ok(Json(json!({ "user": s.store.user(id)? })))
}

async fn delete_user(State(s): State<Shared>, Admin(a): Admin, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require_recent(&a)?;
    if id == a.user.id {
        return Err(ApiError::bad("you can't delete your own account"));
    }
    let target = s.store.user(id)?;
    s.store.delete_user(id)?;
    audit(&s, "user.deleted", Some(&a.user.username), &a.ip, json!({ "user": target.username }));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct SetPasswordReq {
    password: String,
}

async fn admin_set_password(
    State(s): State<Shared>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Json(r): Json<SetPasswordReq>,
) -> ApiResult<Json<Value>> {
    require_recent(&a)?;
    let target = s.store.user(id)?;
    s.store.set_password(id, &r.password, None)?;
    audit(
        &s,
        "user.password_changed",
        Some(&a.user.username),
        &a.ip,
        json!({ "user": target.username, "by": "admin" }),
    );
    Ok(Json(json!({ "ok": true })))
}

async fn unlock_user(State(s): State<Shared>, Admin(a): Admin, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let target = s.store.user(id)?;
    s.store.unlock(id)?;
    audit(&s, "user.unlocked", Some(&a.user.username), &a.ip, json!({ "user": target.username }));
    Ok(Json(json!({ "ok": true })))
}

async fn end_user_sessions(State(s): State<Shared>, Admin(a): Admin, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let target = s.store.user(id)?;
    let n = s.store.delete_user_sessions(id)?;
    audit(&s, "user.sessions_ended", Some(&a.user.username), &a.ip, json!({ "user": target.username, "count": n }));
    Ok(Json(json!({ "ended": n })))
}

// ---------- libraries (admin) ----------

async fn list_libraries(State(s): State<Shared>, Admin(_): Admin) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "libraries": s.store.list_libraries()?, "mode": s.cfg.mode })))
}

#[derive(Deserialize)]
struct AddLibraryReq {
    name: String,
    path: String,
    display_prefix: Option<String>,
}

fn validate_library_path(s: &Shared, raw: &str) -> ApiResult<PathBuf> {
    let p = PathBuf::from(raw.trim());
    if !p.is_absolute() {
        return Err(ApiError::bad("use a full folder path"));
    }
    let canon = std::fs::canonicalize(&p).map_err(|_| ApiError::bad("that folder doesn't exist or can't be read"))?;
    if !canon.is_dir() {
        return Err(ApiError::bad("that path isn't a folder"));
    }
    if let Ok(data) = std::fs::canonicalize(&s.cfg.data_dir) {
        if canon.starts_with(&data) {
            return Err(ApiError::bad("the Gogo Desktop data folder can't be a library"));
        }
    }
    if s.cfg.mode == Mode::Docker {
        let root = s.cfg.libraries_root.clone().unwrap_or_else(|| PathBuf::from("/libraries"));
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        if !canon.starts_with(&root) {
            return Err(ApiError::bad("in the container, libraries must be folders mounted under /libraries"));
        }
    }
    Ok(p)
}

async fn add_library(State(s): State<Shared>, Admin(a): Admin, Json(r): Json<AddLibraryReq>) -> ApiResult<Json<Value>> {
    require_recent(&a)?;
    let path = validate_library_path(&s, &r.path)?;
    let prefix = r.display_prefix.as_deref().map(str::trim).filter(|p| !p.is_empty());
    let lib = s.store.add_library(r.name.trim(), &path.to_string_lossy(), prefix, "admin")?;
    s.start_libraries()?;
    audit(&s, "library.added", Some(&a.user.username), &a.ip, json!({ "library": lib.name, "path": lib.path }));
    Ok(Json(json!({ "library": lib })))
}

#[derive(Deserialize)]
struct UpdateLibraryReq {
    display_prefix: Option<String>,
    excludes: Option<Vec<String>>,
}

async fn update_library(
    State(s): State<Shared>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Json(r): Json<UpdateLibraryReq>,
) -> ApiResult<Json<Value>> {
    let cur = s.store.library(id)?;
    let prefix = match &r.display_prefix {
        Some(p) if p.trim().is_empty() => None,
        Some(p) => Some(p.trim().to_string()),
        None => cur.display_prefix.clone(),
    };
    let excludes = r.excludes.clone().unwrap_or(cur.excludes.clone());
    let lib = s.store.update_library(id, prefix.as_deref(), &excludes)?;
    if r.excludes.is_some() {
        s.restart_library(id)?;
    }
    audit(
        &s,
        "library.updated",
        Some(&a.user.username),
        &a.ip,
        json!({ "library": lib.name, "display_prefix": lib.display_prefix, "excludes": lib.excludes }),
    );
    Ok(Json(json!({ "library": lib })))
}

#[derive(Deserialize)]
struct RemoveLibraryReq {
    confirm_name: String,
}

async fn remove_library(
    State(s): State<Shared>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Json(r): Json<RemoveLibraryReq>,
) -> ApiResult<Json<Value>> {
    require_recent(&a)?;
    let lib = s.store.library(id)?;
    if r.confirm_name.trim() != lib.name {
        return Err(ApiError::bad("type the library name exactly to confirm"));
    }
    if lib.source == "config" && s.cfg.mode == Mode::Docker {
        return Err(ApiError::bad(
            "this library comes from a container mount; remove the mount from compose.yaml instead",
        ));
    }
    s.stop_library(id);
    s.store.remove_library(id)?;
    audit(&s, "library.removed", Some(&a.user.username), &a.ip, json!({ "library": lib.name, "path": lib.path }));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct AccessReq {
    principals: Vec<String>,
}

async fn set_library_access(
    State(s): State<Shared>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Json(r): Json<AccessReq>,
) -> ApiResult<Json<Value>> {
    require_recent(&a)?;
    if r.principals.len() > 1000 {
        return Err(ApiError::bad("too many entries"));
    }
    let lib = s.store.set_library_access(id, &r.principals)?;
    audit(
        &s,
        "library.access_changed",
        Some(&a.user.username),
        &a.ip,
        json!({ "library": lib.name, "access": lib.access }),
    );
    Ok(Json(json!({ "library": lib })))
}

async fn recheck_library(State(s): State<Shared>, Admin(a): Admin, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let lib = s.store.library(id)?;
    if !s.request_recheck(id) {
        return Err(ApiError::not_found());
    }
    audit(&s, "library.recheck", Some(&a.user.username), &a.ip, json!({ "library": lib.name }));
    Ok(Json(json!({ "ok": true })))
}

// ---------- audit ----------

#[derive(Deserialize)]
struct AuditParams {
    limit: Option<usize>,
    prefix: Option<String>,
}

async fn audit_tail(State(s): State<Shared>, Admin(_): Admin, Query(p): Query<AuditParams>) -> ApiResult<Json<Value>> {
    let recs = s.audit.tail(p.limit.unwrap_or(100).min(1000), p.prefix.as_deref()).map_err(|e| anyhow::anyhow!(e))?;
    Ok(Json(json!({ "records": recs })))
}
