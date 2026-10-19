//! SQLite-backed store: users, sessions, libraries and permissions, reset codes.

use crate::{normalize_code, now, password, random_code, random_token, sha256_hex, totp};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;

const SCHEMA_VERSION: i64 = 1;

/// Errors from the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("not found")]
    NotFound,
    #[error("there must always be at least one enabled Gogo Desktop administrator account")]
    LastAdmin,
    #[error("password: {0}")]
    Password(#[from] password::PasswordProblem),
    #[error("that name is already used")]
    Duplicate,
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Sign-in failures. `InvalidCredentials` is deliberately vague.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("wrong username or password")]
    InvalidCredentials,
    #[error("account temporarily locked after repeated failed sign-ins")]
    Locked { until: i64 },
    #[error("enter the code from your authenticator app")]
    CodeRequired,
    #[error("wrong or expired code")]
    BadCode,
    #[error("this account can't sign in here")]
    NotAllowed,
}

/// User roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "user" => Some(Role::User),
            _ => None,
        }
    }
}

/// Account kinds. Synology SSO accounts arrive in milestone M6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountKind {
    /// Gogo Desktop account with a password.
    Local,
    /// Windows user signed in on the same PC.
    Windows,
}

impl AccountKind {
    fn parse(s: &str) -> AccountKind {
        if s == "windows" {
            AccountKind::Windows
        } else {
            AccountKind::Local
        }
    }
}

/// A user account (never includes secrets).
#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub kind: AccountKind,
    pub role: Role,
    pub disabled: bool,
    pub totp_enabled: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    pub locked_until: i64,
}

/// Session rules.
#[derive(Clone, Copy, Debug)]
pub struct SessionPolicy {
    pub idle_secs: i64,
    pub absolute_secs: i64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self { idle_secs: 8 * 3600, absolute_secs: 7 * 86_400 }
    }
}

/// A live session.
#[derive(Clone, Debug, Serialize)]
pub struct Session {
    #[serde(skip)]
    pub id_hash: String,
    pub user_id: i64,
    pub csrf: String,
    pub method: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub expires_at: i64,
    pub reauth_at: i64,
    pub ip: String,
}

/// A configured library.
#[derive(Clone, Debug, Serialize)]
pub struct Library {
    pub id: i64,
    pub name: String,
    pub path: String,
    pub display_prefix: Option<String>,
    pub excludes: Vec<String>,
    /// `config` (from the container mounts or settings file) or `admin` (added in the web page).
    pub source: String,
    /// Principals allowed to search: `user:<id>` or `role:user` (all users). Admins always can.
    pub access: Vec<String>,
}

const FAILS_BEFORE_LOCK: i64 = 5;
const LOCK_SECS: i64 = 15 * 60;

/// The account store.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Opens (or creates) the database file.
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| StoreError::Invalid(e.to_string()))?;
        }
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                kind TEXT NOT NULL,
                external_id TEXT UNIQUE,
                role TEXT NOT NULL,
                pw_hash TEXT,
                totp_secret TEXT,
                totp_pending TEXT,
                totp_last_step INTEGER NOT NULL DEFAULT 0,
                disabled INTEGER NOT NULL DEFAULT 0,
                failed_count INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                last_login_at INTEGER);
            CREATE TABLE IF NOT EXISTS sessions(
                id_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf TEXT NOT NULL,
                method TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                reauth_at INTEGER NOT NULL,
                ip TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS libraries(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                path TEXT NOT NULL,
                display_prefix TEXT,
                excludes TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL,
                created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS library_access(
                library_id INTEGER NOT NULL REFERENCES libraries(id) ON DELETE CASCADE,
                principal TEXT NOT NULL,
                PRIMARY KEY(library_id, principal));
            CREATE TABLE IF NOT EXISTS reset_codes(
                code_hash TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0);",
        )?;
        let version: Option<i64> = conn
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|v| v.parse().ok());
        match version {
            None => {
                conn.execute("INSERT INTO meta(key,value) VALUES('schema_version',?1)", [SCHEMA_VERSION.to_string()])?;
            }
            Some(v) if v > SCHEMA_VERSION => {
                return Err(StoreError::Invalid(format!(
                    "the account database is from a newer Gogo Desktop (schema {v}); update the program"
                )));
            }
            Some(_) => {}
        }
        Ok(Store { conn: Mutex::new(conn) })
    }

    // ---------- users ----------

    fn row_user(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
        Ok(User {
            id: r.get("id")?,
            username: r.get("username")?,
            kind: AccountKind::parse(&r.get::<_, String>("kind")?),
            role: Role::parse(&r.get::<_, String>("role")?).unwrap_or(Role::User),
            disabled: r.get::<_, i64>("disabled")? != 0,
            totp_enabled: r.get::<_, Option<String>>("totp_secret")?.is_some(),
            created_at: r.get("created_at")?,
            last_login_at: r.get("last_login_at")?,
            locked_until: r.get("locked_until")?,
        })
    }

    /// Checks a username for a Gogo Desktop account.
    pub fn validate_username(name: &str) -> Result<()> {
        let ok = (2..=64).contains(&name.chars().count())
            && name.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
            && !name.starts_with(['.', '-']);
        if ok {
            Ok(())
        } else {
            Err(StoreError::Invalid(
                "usernames use 2-64 letters, digits, '.', '_', '-' or '@', and can't start with '.' or '-'".into(),
            ))
        }
    }

    /// Number of enabled Gogo Desktop (local) administrators.
    pub fn local_admin_count(&self) -> Result<i64> {
        Ok(self.conn.lock().query_row(
            "SELECT COUNT(*) FROM users WHERE kind='local' AND role='admin' AND disabled=0",
            [],
            |r| r.get(0),
        )?)
    }

    /// Creates a Gogo Desktop account.
    pub fn create_local_user(&self, username: &str, pw: &str, role: Role) -> Result<User> {
        Self::validate_username(username)?;
        password::check_rules(pw, username)?;
        let hash = password::hash(pw);
        let conn = self.conn.lock();
        let res = conn.execute(
            "INSERT INTO users(username,kind,role,pw_hash,created_at) VALUES(?1,'local',?2,?3,?4)",
            params![username, role.as_str(), hash, now()],
        );
        match res {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                return Err(StoreError::Duplicate)
            }
            Err(e) => return Err(e.into()),
        }
        let id = conn.last_insert_rowid();
        drop(conn);
        self.user(id)
    }

    /// Finds or creates the account for a Windows user (same-PC sign-in).
    /// New Windows accounts get the User role and no library access.
    pub fn windows_user(&self, sid: &str, display: &str) -> Result<User> {
        let conn = self.conn.lock();
        let existing: Option<i64> = conn
            .query_row("SELECT id FROM users WHERE kind='windows' AND external_id=?1", [sid], |r| r.get(0))
            .optional()?;
        let id = match existing {
            Some(id) => {
                conn.execute("UPDATE users SET username=?1 WHERE id=?2", params![display, id]).ok();
                id
            }
            None => {
                conn.execute(
                    "INSERT INTO users(username,kind,external_id,role,created_at) VALUES(?1,'windows',?2,'user',?3)",
                    params![display, sid, now()],
                )?;
                conn.last_insert_rowid()
            }
        };
        drop(conn);
        self.user(id)
    }

    pub fn user(&self, id: i64) -> Result<User> {
        self.conn
            .lock()
            .query_row("SELECT * FROM users WHERE id=?1", [id], Self::row_user)
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    pub fn user_by_name(&self, username: &str) -> Result<Option<User>> {
        Ok(self
            .conn
            .lock()
            .query_row("SELECT * FROM users WHERE username=?1", [username], Self::row_user)
            .optional()?)
    }

    pub fn list_users(&self) -> Result<Vec<User>> {
        let conn = self.conn.lock();
        let mut st = conn.prepare("SELECT * FROM users ORDER BY username COLLATE NOCASE")?;
        let rows = st.query_map([], Self::row_user)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Would this change leave no enabled local administrator?
    fn guard_last_admin(&self, id: i64) -> Result<()> {
        let u = self.user(id)?;
        if u.kind == AccountKind::Local && u.role == Role::Admin && !u.disabled && self.local_admin_count()? <= 1 {
            return Err(StoreError::LastAdmin);
        }
        Ok(())
    }

    pub fn set_role(&self, id: i64, role: Role) -> Result<User> {
        if role == Role::User {
            self.guard_last_admin(id)?;
        }
        self.conn.lock().execute("UPDATE users SET role=?1 WHERE id=?2", params![role.as_str(), id])?;
        self.user(id)
    }

    /// Disables or enables an account. Disabling ends its sessions.
    pub fn set_disabled(&self, id: i64, disabled: bool) -> Result<User> {
        if disabled {
            self.guard_last_admin(id)?;
        }
        let conn = self.conn.lock();
        conn.execute("UPDATE users SET disabled=?1 WHERE id=?2", params![disabled as i64, id])?;
        if disabled {
            conn.execute("DELETE FROM sessions WHERE user_id=?1", [id])?;
        }
        drop(conn);
        self.user(id)
    }

    pub fn delete_user(&self, id: i64) -> Result<()> {
        self.guard_last_admin(id)?;
        let conn = self.conn.lock();
        conn.execute("DELETE FROM library_access WHERE principal=?1", [format!("user:{id}")])?;
        let n = conn.execute("DELETE FROM users WHERE id=?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Signs in a Gogo Desktop account. Applies lockout and the second factor.
    pub fn authenticate_local(
        &self,
        username: &str,
        pw: &str,
        code: Option<&str>,
        admins_only: bool,
    ) -> std::result::Result<User, AuthError> {
        let t = now();
        type Row = (i64, Option<String>, Option<String>, i64, i64, i64, String, String, i64);
        let row: Option<Row> = self
            .conn
            .lock()
            .query_row(
                "SELECT id,pw_hash,totp_secret,totp_last_step,failed_count,locked_until,role,kind,disabled FROM users WHERE username=?1",
                [username],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
            )
            .optional()
            .map_err(|_| AuthError::InvalidCredentials)?;
        let Some((id, hash, secret, last_step, fails, locked_until, role, kind, disabled)) = row else {
            password::dummy_verify(pw);
            return Err(AuthError::InvalidCredentials);
        };
        if locked_until > t {
            password::dummy_verify(pw);
            return Err(AuthError::Locked { until: locked_until });
        }
        let Some(hash) = hash.filter(|_| kind == "local") else {
            password::dummy_verify(pw);
            return Err(AuthError::InvalidCredentials);
        };
        if !password::verify(pw, &hash) {
            self.record_failure(id, fails);
            return Err(AuthError::InvalidCredentials);
        }
        if disabled != 0 {
            return Err(AuthError::InvalidCredentials);
        }
        if admins_only && role != "admin" {
            return Err(AuthError::NotAllowed);
        }
        if let Some(secret) = secret {
            let Some(code) = code.filter(|c| !c.trim().is_empty()) else {
                return Err(AuthError::CodeRequired);
            };
            match totp::verify(&secret, code, t, last_step) {
                Some(step) => {
                    let _ =
                        self.conn.lock().execute("UPDATE users SET totp_last_step=?1 WHERE id=?2", params![step, id]);
                }
                None => {
                    self.record_failure(id, fails);
                    return Err(AuthError::BadCode);
                }
            }
        }
        let _ = self
            .conn
            .lock()
            .execute("UPDATE users SET failed_count=0, locked_until=0, last_login_at=?1 WHERE id=?2", params![t, id]);
        self.user(id).map_err(|_| AuthError::InvalidCredentials)
    }

    /// Checks the password (and code, if enabled) of a signed-in local account,
    /// for "confirm it's you" before risky actions.
    pub fn verify_local(&self, id: i64, pw: &str, code: Option<&str>) -> std::result::Result<(), AuthError> {
        let u = self.user(id).map_err(|_| AuthError::InvalidCredentials)?;
        self.authenticate_local(&u.username, pw, code, false).map(|_| ())
    }

    fn record_failure(&self, id: i64, fails: i64) {
        let fails = fails + 1;
        let conn = self.conn.lock();
        if fails >= FAILS_BEFORE_LOCK {
            let _ = conn.execute(
                "UPDATE users SET failed_count=0, locked_until=?1 WHERE id=?2",
                params![now() + LOCK_SECS, id],
            );
        } else {
            let _ = conn.execute("UPDATE users SET failed_count=?1 WHERE id=?2", params![fails, id]);
        }
    }

    /// Clears a lockout (administrator action).
    pub fn unlock(&self, id: i64) -> Result<()> {
        self.conn.lock().execute("UPDATE users SET failed_count=0, locked_until=0 WHERE id=?1", [id])?;
        Ok(())
    }

    /// Changes a local account's password and ends its other sessions.
    pub fn set_password(&self, id: i64, new_pw: &str, keep_session: Option<&str>) -> Result<()> {
        let u = self.user(id)?;
        if u.kind != AccountKind::Local {
            return Err(StoreError::Invalid("only Gogo Desktop accounts have passwords".into()));
        }
        password::check_rules(new_pw, &u.username)?;
        let hash = password::hash(new_pw);
        let conn = self.conn.lock();
        conn.execute("UPDATE users SET pw_hash=?1, failed_count=0, locked_until=0 WHERE id=?2", params![hash, id])?;
        match keep_session {
            Some(token) => conn.execute(
                "DELETE FROM sessions WHERE user_id=?1 AND id_hash<>?2",
                params![id, sha256_hex(token.as_bytes())],
            )?,
            None => conn.execute("DELETE FROM sessions WHERE user_id=?1", [id])?,
        };
        Ok(())
    }

    /// Starts second-factor setup: returns a new secret (not active until confirmed).
    pub fn totp_begin(&self, id: i64) -> Result<String> {
        let secret = totp::new_secret();
        self.conn.lock().execute("UPDATE users SET totp_pending=?1 WHERE id=?2", params![secret, id])?;
        Ok(secret)
    }

    /// Confirms second-factor setup with a code from the app.
    pub fn totp_confirm(&self, id: i64, code: &str) -> Result<()> {
        let pending: Option<String> = self
            .conn
            .lock()
            .query_row("SELECT totp_pending FROM users WHERE id=?1", [id], |r| r.get(0))
            .optional()?
            .flatten();
        let pending = pending.ok_or_else(|| StoreError::Invalid("start setup first".into()))?;
        let step = totp::verify(&pending, code, now(), 0).ok_or_else(|| StoreError::Invalid("wrong code".into()))?;
        self.conn.lock().execute(
            "UPDATE users SET totp_secret=totp_pending, totp_pending=NULL, totp_last_step=?1 WHERE id=?2",
            params![step, id],
        )?;
        Ok(())
    }

    /// Enables the second factor with a secret the user already scanned,
    /// after checking a code from it (used during first-run setup).
    pub fn totp_enable_with(&self, id: i64, secret: &str, code: &str) -> Result<()> {
        let step = totp::verify(secret, code, now(), 0).ok_or_else(|| StoreError::Invalid("wrong code".into()))?;
        self.conn.lock().execute(
            "UPDATE users SET totp_secret=?1, totp_pending=NULL, totp_last_step=?2 WHERE id=?3",
            params![secret, step, id],
        )?;
        Ok(())
    }

    /// Turns off the second factor.
    pub fn totp_disable(&self, id: i64) -> Result<()> {
        self.conn
            .lock()
            .execute("UPDATE users SET totp_secret=NULL, totp_pending=NULL, totp_last_step=0 WHERE id=?1", [id])?;
        Ok(())
    }

    // ---------- sessions ----------

    /// Creates a session; returns (token for the cookie, session).
    pub fn create_session(
        &self,
        user_id: i64,
        method: &str,
        ip: &str,
        policy: SessionPolicy,
    ) -> Result<(String, Session)> {
        let token = random_token(32);
        let t = now();
        let s = Session {
            id_hash: sha256_hex(token.as_bytes()),
            user_id,
            csrf: random_token(32),
            method: method.to_string(),
            created_at: t,
            last_seen: t,
            expires_at: t + policy.absolute_secs,
            reauth_at: t,
            ip: ip.to_string(),
        };
        let conn = self.conn.lock();
        conn.execute("DELETE FROM sessions WHERE expires_at<?1 OR last_seen<?2", params![t, t - policy.idle_secs])?;
        conn.execute(
            "INSERT INTO sessions(id_hash,user_id,csrf,method,created_at,last_seen,expires_at,reauth_at,ip)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![s.id_hash, s.user_id, s.csrf, s.method, s.created_at, s.last_seen, s.expires_at, s.reauth_at, s.ip],
        )?;
        Ok((token, s))
    }

    /// Looks up a session by cookie token, applying idle and absolute limits.
    /// Disabled accounts have no valid sessions.
    pub fn session(&self, token: &str, policy: SessionPolicy) -> Result<Option<(Session, User)>> {
        if token.len() > 128 {
            return Ok(None);
        }
        let h = sha256_hex(token.as_bytes());
        let t = now();
        let row = self
            .conn
            .lock()
            .query_row(
                "SELECT user_id,csrf,method,created_at,last_seen,expires_at,reauth_at,ip FROM sessions WHERE id_hash=?1",
                [&h],
                |r| {
                    Ok(Session {
                        id_hash: h.clone(),
                        user_id: r.get(0)?,
                        csrf: r.get(1)?,
                        method: r.get(2)?,
                        created_at: r.get(3)?,
                        last_seen: r.get(4)?,
                        expires_at: r.get(5)?,
                        reauth_at: r.get(6)?,
                        ip: r.get(7)?,
                    })
                },
            )
            .optional()?;
        let Some(s) = row else { return Ok(None) };
        if s.expires_at <= t || s.last_seen + policy.idle_secs <= t {
            self.conn.lock().execute("DELETE FROM sessions WHERE id_hash=?1", [&h])?;
            return Ok(None);
        }
        let user = match self.user(s.user_id) {
            Ok(u) if !u.disabled => u,
            _ => return Ok(None),
        };
        if t - s.last_seen >= 60 {
            self.conn.lock().execute("UPDATE sessions SET last_seen=?1 WHERE id_hash=?2", params![t, h])?;
        }
        Ok(Some((s, user)))
    }

    /// Records a fresh "confirm it's you" for the session.
    pub fn mark_reauth(&self, token: &str) -> Result<()> {
        self.conn.lock().execute(
            "UPDATE sessions SET reauth_at=?1 WHERE id_hash=?2",
            params![now(), sha256_hex(token.as_bytes())],
        )?;
        Ok(())
    }

    pub fn delete_session(&self, token: &str) -> Result<()> {
        self.conn.lock().execute("DELETE FROM sessions WHERE id_hash=?1", [sha256_hex(token.as_bytes())])?;
        Ok(())
    }

    pub fn delete_user_sessions(&self, user_id: i64) -> Result<usize> {
        Ok(self.conn.lock().execute("DELETE FROM sessions WHERE user_id=?1", [user_id])?)
    }

    /// Ends every session of a user except the one with `keep_token`.
    pub fn delete_user_sessions_except(&self, user_id: i64, keep_token: &str) -> Result<usize> {
        Ok(self.conn.lock().execute(
            "DELETE FROM sessions WHERE user_id=?1 AND id_hash<>?2",
            params![user_id, sha256_hex(keep_token.as_bytes())],
        )?)
    }

    /// Test helper: makes the last "confirm it's you" `secs` older.
    #[doc(hidden)]
    pub fn age_reauth_for_tests(&self, token: &str, secs: i64) {
        let _ = self.conn.lock().execute(
            "UPDATE sessions SET reauth_at=reauth_at-?1 WHERE id_hash=?2",
            params![secs, sha256_hex(token.as_bytes())],
        );
    }

    pub fn delete_all_sessions(&self) -> Result<usize> {
        Ok(self.conn.lock().execute("DELETE FROM sessions", [])?)
    }

    pub fn list_sessions(&self, user_id: i64) -> Result<Vec<Session>> {
        let conn = self.conn.lock();
        let mut st = conn.prepare(
            "SELECT id_hash,user_id,csrf,method,created_at,last_seen,expires_at,reauth_at,ip FROM sessions WHERE user_id=?1 ORDER BY last_seen DESC",
        )?;
        let rows = st
            .query_map([user_id], |r| {
                Ok(Session {
                    id_hash: r.get(0)?,
                    user_id: r.get(1)?,
                    csrf: String::new(),
                    method: r.get(3)?,
                    created_at: r.get(4)?,
                    last_seen: r.get(5)?,
                    expires_at: r.get(6)?,
                    reauth_at: r.get(7)?,
                    ip: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---------- libraries ----------

    fn validate_library_name(name: &str) -> Result<()> {
        let ok = (1..=64).contains(&name.chars().count())
            && name.chars().all(|c| c.is_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
            && !name.trim().is_empty();
        if ok {
            Ok(())
        } else {
            Err(StoreError::Invalid("library names use 1-64 letters, digits, spaces, '.', '_' or '-'".into()))
        }
    }

    /// Adds a library. New libraries are visible to administrators only.
    pub fn add_library(&self, name: &str, path: &str, display_prefix: Option<&str>, source: &str) -> Result<Library> {
        Self::validate_library_name(name)?;
        let conn = self.conn.lock();
        let res = conn.execute(
            "INSERT INTO libraries(name,path,display_prefix,source,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![name, path, display_prefix, source, now()],
        );
        match res {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                return Err(StoreError::Duplicate)
            }
            Err(e) => return Err(e.into()),
        }
        let id = conn.last_insert_rowid();
        if id > u16::MAX as i64 {
            return Err(StoreError::Invalid("too many libraries".into()));
        }
        drop(conn);
        self.library(id)
    }

    pub fn library(&self, id: i64) -> Result<Library> {
        self.list_libraries()?.into_iter().find(|l| l.id == id).ok_or(StoreError::NotFound)
    }

    pub fn list_libraries(&self) -> Result<Vec<Library>> {
        let conn = self.conn.lock();
        let mut st = conn.prepare(
            "SELECT id,name,path,display_prefix,excludes,source FROM libraries ORDER BY name COLLATE NOCASE",
        )?;
        let mut libs = st
            .query_map([], |r| {
                let ex: String = r.get(4)?;
                Ok(Library {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    path: r.get(2)?,
                    display_prefix: r.get(3)?,
                    excludes: serde_json::from_str(&ex).unwrap_or_default(),
                    source: r.get(5)?,
                    access: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut st = conn.prepare("SELECT principal FROM library_access WHERE library_id=?1 ORDER BY principal")?;
        for l in &mut libs {
            l.access = st.query_map([l.id], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        }
        Ok(libs)
    }

    pub fn update_library(&self, id: i64, display_prefix: Option<&str>, excludes: &[String]) -> Result<Library> {
        if excludes.len() > 200 || excludes.iter().any(|e| e.is_empty() || e.len() > 200) {
            return Err(StoreError::Invalid("up to 200 exclusion patterns of 1-200 characters".into()));
        }
        let n = self.conn.lock().execute(
            "UPDATE libraries SET display_prefix=?1, excludes=?2 WHERE id=?3",
            params![display_prefix, serde_json::to_string(excludes).unwrap_or_else(|_| "[]".into()), id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        self.library(id)
    }

    pub fn remove_library(&self, id: i64) -> Result<()> {
        let n = self.conn.lock().execute("DELETE FROM libraries WHERE id=?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Replaces who may search a library.
    pub fn set_library_access(&self, id: i64, principals: &[String]) -> Result<Library> {
        for p in principals {
            let ok = p == "role:user"
                || p.strip_prefix("user:")
                    .and_then(|v| v.parse::<i64>().ok())
                    .map(|uid| self.user(uid).is_ok())
                    .unwrap_or(false);
            if !ok {
                return Err(StoreError::Invalid(format!("unknown principal '{p}'")));
            }
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM library_access WHERE library_id=?1", [id])?;
        for p in principals {
            tx.execute("INSERT OR IGNORE INTO library_access(library_id,principal) VALUES(?1,?2)", params![id, p])?;
        }
        tx.commit()?;
        drop(conn);
        self.library(id)
    }

    /// Library IDs a user may search. Administrators see every library.
    pub fn libraries_for(&self, user: &User) -> Result<Vec<i64>> {
        if user.role == Role::Admin {
            return Ok(self.list_libraries()?.into_iter().map(|l| l.id).collect());
        }
        let conn = self.conn.lock();
        let mut st =
            conn.prepare("SELECT DISTINCT library_id FROM library_access WHERE principal='role:user' OR principal=?1")?;
        let ids = st.query_map([format!("user:{}", user.id)], |r| r.get(0))?.collect::<rusqlite::Result<Vec<i64>>>()?;
        Ok(ids)
    }

    // ---------- recovery ----------

    /// Creates a one-time reset code (valid 15 minutes) and returns it.
    pub fn create_reset_code(&self) -> Result<String> {
        let code = random_code();
        self.conn.lock().execute(
            "INSERT INTO reset_codes(code_hash,expires_at) VALUES(?1,?2)",
            params![sha256_hex(normalize_code(&code).as_bytes()), now() + 15 * 60],
        )?;
        Ok(code)
    }

    /// Uses a reset code: sets a new password for a local administrator,
    /// clears its lockout and second factor, and ends its sessions.
    pub fn use_reset_code(&self, code: &str, username: &str, new_pw: &str) -> Result<User> {
        let h = sha256_hex(normalize_code(code).as_bytes());
        let valid: Option<i64> = self
            .conn
            .lock()
            .query_row("SELECT expires_at FROM reset_codes WHERE code_hash=?1 AND used=0", [&h], |r| r.get(0))
            .optional()?;
        if !valid.map(|e| e > now()).unwrap_or(false) {
            return Err(StoreError::Invalid("the reset code is wrong, used or expired".into()));
        }
        let user = self
            .user_by_name(username)?
            .filter(|u| u.kind == AccountKind::Local && u.role == Role::Admin)
            .ok_or_else(|| StoreError::Invalid("no Gogo Desktop administrator with that username".into()))?;
        password::check_rules(new_pw, &user.username)?;
        self.conn.lock().execute("UPDATE reset_codes SET used=1 WHERE code_hash=?1", [&h])?;
        self.set_password(user.id, new_pw, None)?;
        self.totp_disable(user.id)?;
        self.conn.lock().execute("UPDATE users SET disabled=0 WHERE id=?1", [user.id])?;
        self.user(user.id)
    }
}

#[cfg(test)]
mod tests;
