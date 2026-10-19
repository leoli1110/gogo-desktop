//! Configuration from environment variables and the administrator policy file.
//!
//! Order of precedence (spec section 3.3.2): `policy.yaml` > environment
//! variables > defaults. Invalid values stop the program with a clear message
//! (fail closed). Administrator approval of Synology users can't be turned off;
//! any attempt to do so is refused at startup.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How the program is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Windows PC (service or console).
    Windows,
    /// Docker container (Synology NAS).
    Docker,
    /// Any other host (development, plain Linux).
    Standalone,
}

/// Which Gogo Desktop accounts may sign in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAccounts {
    All,
    AdminsOnly,
}

/// A library defined by configuration (container mounts or `GOGO_LIBRARIES`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigLibrary {
    pub name: String,
    pub path: PathBuf,
}

/// Effective configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    pub data_dir: PathBuf,
    pub config_dir: Option<PathBuf>,
    pub http_bind: Option<SocketAddr>,
    pub https_bind: Option<SocketAddr>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub public_url: Option<String>,
    pub allowed_hosts: Vec<String>,
    pub trust_proxy: bool,
    pub local_accounts: LocalAccounts,
    pub require_totp_for_local_admins: bool,
    pub session_idle: Duration,
    pub session_max: Duration,
    pub recheck_interval: Duration,
    pub audit_retention_days: i64,
    pub approval_pending_max: u32,
    pub approval_expiry_days: u32,
    pub sso_enabled: bool,
    pub libraries: Vec<ConfigLibrary>,
    pub libraries_root: Option<PathBuf>,
    pub profile: String,
    /// Settings locked by `policy.yaml` or environment variables (shown read-only).
    pub locked: Vec<String>,
}

/// `policy.yaml` (spec section 3.3.3). Unknown keys are errors.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub sign_in: Option<PolicySignIn>,
    #[serde(default)]
    pub approval: Option<PolicyApproval>,
    #[serde(default)]
    pub users: Option<PolicyUsers>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignIn {
    pub local_accounts: Option<LocalAccounts>,
    pub sso_enabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyApproval {
    pub pending_max: Option<u32>,
    pub expiry_days: Option<u32>,
    /// Applied with Synology approvals in milestone M6.
    #[allow(dead_code)]
    pub admin_role_requires_two_admins: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUsers {
    pub require_totp_for_local_admins: Option<bool>,
}

/// Environment variables that would weaken administrator approval. Refused.
const FORBIDDEN_VARS: &[&str] = &[
    "GOGO_SSO_REQUIRE_APPROVAL",
    "GOGO_SSO_AUTO_APPROVE",
    "GOGO_APPROVAL_DISABLED",
    "GOGO_APPROVAL_REQUIRED",
    "GOGO_DISABLE_APPROVAL",
    "GOGO_AUTO_APPROVE",
];

/// Environment variables that must never carry a secret directly.
const SECRET_VARS: &[&str] = &["GOGO_SSO_CLIENT_SECRET", "GOGO_TLS_KEY"];

pub const APPROVAL_MANDATORY: &str = "Administrator approval of Synology users is mandatory and cannot be disabled.";

fn parse_bool(name: &str, v: &str) -> Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("{name}: expected true or false, got '{v}'"),
    }
}

fn parse_range(name: &str, v: &str, lo: i64, hi: i64) -> Result<i64> {
    let n: i64 = v.trim().parse().map_err(|_| anyhow!("{name}: expected a number, got '{v}'"))?;
    if !(lo..=hi).contains(&n) {
        bail!("{name}: {n} is outside the allowed range {lo}-{hi}");
    }
    Ok(n)
}

fn parse_bind(name: &str, v: &str) -> Result<Option<SocketAddr>> {
    let v = v.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    v.parse().map(Some).map_err(|_| anyhow!("{name}: expected an address like 127.0.0.1:4680 or 'off', got '{v}'"))
}

/// Parses `Name=Path;Name2=Path2` (Windows `GOGO_LIBRARIES`).
pub fn parse_libraries(v: &str) -> Result<Vec<ConfigLibrary>> {
    let mut out = Vec::new();
    for part in v.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (name, path) =
            part.split_once('=').ok_or_else(|| anyhow!("GOGO_LIBRARIES: expected Name=Path, got '{part}'"))?;
        let path = PathBuf::from(path.trim());
        if !path.is_absolute() {
            bail!("GOGO_LIBRARIES: '{}' must be an absolute path", path.display());
        }
        out.push(ConfigLibrary { name: name.trim().to_string(), path });
    }
    Ok(out)
}

fn detect_mode(env: &HashMap<String, String>) -> Mode {
    match env.get("GOGO_MODE").map(|s| s.to_ascii_lowercase()) {
        Some(m) if m == "docker" => return Mode::Docker,
        Some(m) if m == "windows" => return Mode::Windows,
        Some(m) if m == "standalone" => return Mode::Standalone,
        _ => {}
    }
    if cfg!(windows) {
        Mode::Windows
    } else if Path::new("/.dockerenv").exists() {
        Mode::Docker
    } else {
        Mode::Standalone
    }
}

fn default_data_dir(mode: Mode) -> PathBuf {
    match mode {
        Mode::Docker => PathBuf::from("/data"),
        Mode::Windows => std::env::var_os("ProgramData")
            .map(|p| PathBuf::from(p).join("GogoDesktop"))
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\GogoDesktop")),
        Mode::Standalone => PathBuf::from("./gogo-data"),
    }
}

impl Config {
    /// Loads configuration from the process environment.
    pub fn from_env() -> Result<Config> {
        let env: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&env)
    }

    /// Loads configuration from a map of variables (testable).
    pub fn from_map(env: &HashMap<String, String>) -> Result<Config> {
        for v in FORBIDDEN_VARS {
            if env.contains_key(*v) {
                bail!("{v} is not allowed. {APPROVAL_MANDATORY}");
            }
        }
        for v in SECRET_VARS {
            if env.contains_key(*v) {
                bail!("{v} is not allowed: put secrets in a file and use {v}_FILE instead");
            }
        }
        let known_prefix_vars: Vec<&String> = env.keys().filter(|k| k.starts_with("GOGO_")).collect();
        for k in known_prefix_vars {
            if !KNOWN_VARS.contains(&k.as_str()) {
                bail!("unknown setting {k}; check the spelling (see docs/configuration.md)");
            }
        }
        let get = |k: &str| env.get(k).map(|s| s.as_str());
        let mode = detect_mode(env);
        let mut locked = Vec::new();

        let data_dir = get("GOGO_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| default_data_dir(mode));
        let config_dir = match get("GOGO_CONFIG_DIR") {
            Some(d) => Some(PathBuf::from(d)),
            None if mode == Mode::Docker => Some(PathBuf::from("/config")),
            None => None,
        };

        let (default_http, default_https) = match mode {
            Mode::Docker => ("off", "0.0.0.0:4681"),
            _ => ("127.0.0.1:4680", "off"),
        };
        let http_bind = parse_bind("GOGO_HTTP_BIND", get("GOGO_HTTP_BIND").unwrap_or(default_http))?;
        let https_bind = parse_bind("GOGO_HTTPS_BIND", get("GOGO_HTTPS_BIND").unwrap_or(default_https))?;
        if http_bind.is_none() && https_bind.is_none() {
            bail!("both GOGO_HTTP_BIND and GOGO_HTTPS_BIND are off; nothing to listen on");
        }
        let trust_proxy = parse_bool("GOGO_TRUST_PROXY", get("GOGO_TRUST_PROXY").unwrap_or("false"))?;
        if let Some(a) = http_bind {
            if !a.ip().is_loopback() && !trust_proxy {
                bail!(
                    "GOGO_HTTP_BIND={a}: plain HTTP is only allowed on 127.0.0.1, or behind a reverse proxy \
                     with GOGO_TRUST_PROXY=true. Use GOGO_HTTPS_BIND for network access."
                );
            }
        }
        let public_url = get("GOGO_PUBLIC_URL").map(|s| s.trim_end_matches('/').to_string());
        if let Some(u) = &public_url {
            if !(u.starts_with("https://") || u.starts_with("http://127.0.0.1") || u.starts_with("http://localhost")) {
                bail!("GOGO_PUBLIC_URL must start with https:// (got '{u}')");
            }
        }
        let mut allowed_hosts: Vec<String> = vec!["127.0.0.1".into(), "localhost".into(), "[::1]".into()];
        if let Some(h) = public_url.as_deref().and_then(url_host) {
            allowed_hosts.push(h);
        }
        if let Some(list) = get("GOGO_ALLOWED_HOSTS") {
            for h in list.split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()) {
                if h.contains('/') || h.contains(' ') || h.contains('*') {
                    bail!("GOGO_ALLOWED_HOSTS: '{h}' is not a host name");
                }
                allowed_hosts.push(h);
            }
        }

        let mut local_accounts = match get("GOGO_LOCAL_ACCOUNTS").unwrap_or("all") {
            "all" => LocalAccounts::All,
            "admins_only" => LocalAccounts::AdminsOnly,
            v => bail!("GOGO_LOCAL_ACCOUNTS: expected all or admins_only, got '{v}'"),
        };
        if get("GOGO_LOCAL_ACCOUNTS").is_some() {
            locked.push("sign_in.local_accounts".into());
        }
        let network_reachable =
            https_bind.map(|a| !a.ip().is_loopback()).unwrap_or(false) || (http_bind.is_some() && trust_proxy);
        let mut require_totp = match get("GOGO_REQUIRE_TOTP_FOR_LOCAL_ADMINS") {
            Some(v) => {
                locked.push("users.require_totp_for_local_admins".into());
                parse_bool("GOGO_REQUIRE_TOTP_FOR_LOCAL_ADMINS", v)?
            }
            None => network_reachable,
        };
        if network_reachable && !require_totp {
            bail!("GOGO_REQUIRE_TOTP_FOR_LOCAL_ADMINS can't be false while the server is reachable from the network");
        }
        let sso_session_hours =
            parse_range("GOGO_SSO_SESSION_MAX_HOURS", get("GOGO_SSO_SESSION_MAX_HOURS").unwrap_or("8"), 1, 24)?;
        let _ = sso_session_hours;
        let session_idle_hours =
            parse_range("GOGO_SESSION_IDLE_HOURS", get("GOGO_SESSION_IDLE_HOURS").unwrap_or("8"), 1, 72)?;
        let session_max_days =
            parse_range("GOGO_SESSION_MAX_DAYS", get("GOGO_SESSION_MAX_DAYS").unwrap_or("7"), 1, 30)?;
        let recheck_hours = parse_range("GOGO_RECHECK_HOURS", get("GOGO_RECHECK_HOURS").unwrap_or("6"), 1, 168)?;
        let audit_retention_days =
            parse_range("GOGO_AUDIT_RETENTION_DAYS", get("GOGO_AUDIT_RETENTION_DAYS").unwrap_or("365"), 90, 3650)?;
        let mut approval_pending_max =
            parse_range("GOGO_APPROVAL_PENDING_MAX", get("GOGO_APPROVAL_PENDING_MAX").unwrap_or("50"), 1, 500)? as u32;
        let mut approval_expiry_days =
            parse_range("GOGO_APPROVAL_EXPIRY_DAYS", get("GOGO_APPROVAL_EXPIRY_DAYS").unwrap_or("30"), 1, 90)? as u32;
        let mut sso_enabled = parse_bool("GOGO_SSO_ENABLED", get("GOGO_SSO_ENABLED").unwrap_or("false"))?;
        let profile = get("GOGO_PROFILE").map(str::to_string).unwrap_or_else(|| {
            if mode == Mode::Docker {
                "nas-small".into()
            } else {
                "windows".into()
            }
        });
        if !["windows", "nas-small", "nas-large"].contains(&profile.as_str()) {
            bail!("GOGO_PROFILE: expected windows, nas-small or nas-large, got '{profile}'");
        }

        let mut libraries = match get("GOGO_LIBRARIES") {
            Some(v) => parse_libraries(v)?,
            None => Vec::new(),
        };
        let libraries_root = match get("GOGO_LIBRARIES_DIR") {
            Some(d) => Some(PathBuf::from(d)),
            None if mode == Mode::Docker => Some(PathBuf::from("/libraries")),
            None => None,
        };
        if let Some(root) = &libraries_root {
            if let Ok(rd) = std::fs::read_dir(root) {
                let mut found: Vec<ConfigLibrary> = rd
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| ConfigLibrary { name: e.file_name().to_string_lossy().into_owned(), path: e.path() })
                    .collect();
                found.sort_by(|a, b| a.name.cmp(&b.name));
                libraries.extend(found);
            }
        }

        // policy.yaml overrides everything, and may only tighten approval.
        if let Some(dir) = &config_dir {
            let p = dir.join("policy.yaml");
            if p.exists() {
                let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
                let policy = parse_policy(&text).with_context(|| format!("in {}", p.display()))?;
                if let Some(s) = policy.sign_in {
                    if let Some(v) = s.local_accounts {
                        local_accounts = v;
                        locked.push("sign_in.local_accounts".into());
                    }
                    if let Some(v) = s.sso_enabled {
                        sso_enabled = v;
                        locked.push("sign_in.sso_enabled".into());
                    }
                }
                if let Some(a) = policy.approval {
                    if let Some(v) = a.pending_max {
                        if !(1..=500).contains(&v) {
                            bail!("policy.yaml approval.pending_max must be 1-500");
                        }
                        approval_pending_max = approval_pending_max.min(v);
                        locked.push("approval.pending_max".into());
                    }
                    if let Some(v) = a.expiry_days {
                        if !(1..=90).contains(&v) {
                            bail!("policy.yaml approval.expiry_days must be 1-90");
                        }
                        approval_expiry_days = approval_expiry_days.min(v);
                        locked.push("approval.expiry_days".into());
                    }
                }
                if let Some(u) = policy.users {
                    if let Some(v) = u.require_totp_for_local_admins {
                        if !v && network_reachable {
                            bail!("policy.yaml users.require_totp_for_local_admins can't be false while the server is reachable from the network");
                        }
                        require_totp = v || require_totp;
                        locked.push("users.require_totp_for_local_admins".into());
                    }
                }
            }
        }
        if sso_enabled {
            tracing::warn!(
                "Synology SSO is planned for milestone M6; GOGO_SSO_ENABLED is accepted but has no effect yet"
            );
        }

        Ok(Config {
            mode,
            data_dir,
            config_dir,
            http_bind,
            https_bind,
            tls_cert: get("GOGO_TLS_CERT_FILE").map(PathBuf::from),
            tls_key: get("GOGO_TLS_KEY_FILE").map(PathBuf::from),
            public_url,
            allowed_hosts,
            trust_proxy,
            local_accounts,
            require_totp_for_local_admins: require_totp,
            session_idle: Duration::from_secs(session_idle_hours as u64 * 3600),
            session_max: Duration::from_secs(session_max_days as u64 * 86_400),
            recheck_interval: Duration::from_secs(recheck_hours as u64 * 3600),
            audit_retention_days,
            approval_pending_max,
            approval_expiry_days,
            sso_enabled,
            libraries,
            libraries_root,
            profile,
            locked,
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("db").join("accounts.sqlite")
    }
    pub fn audit_dir(&self) -> PathBuf {
        self.data_dir.join("audit")
    }
    pub fn tls_dir(&self) -> PathBuf {
        self.data_dir.join("tls")
    }

    /// Startup checks that must pass before serving (spec section 3.3.4).
    pub fn startup_checks(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("can't create the data folder {}", self.data_dir.display()))?;
        #[cfg(windows)]
        crate::winacl::restrict_to_admins(&self.data_dir)
            .with_context(|| format!("can't restrict access to {}", self.data_dir.display()))?;
        let probe = self.data_dir.join(".write-test");
        std::fs::write(&probe, b"ok")
            .with_context(|| format!("the data folder {} isn't writable", self.data_dir.display()))?;
        let _ = std::fs::remove_file(&probe);
        if self.mode == Mode::Docker {
            if let Some(dir) = &self.config_dir {
                if dir.exists() {
                    let probe = dir.join(".write-test");
                    if std::fs::write(&probe, b"x").is_ok() {
                        let _ = std::fs::remove_file(&probe);
                        bail!(
                            "{} is writable from inside the container. Mount it read-only (:ro) so the policy can't be changed from inside.",
                            dir.display()
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Parses and validates policy.yaml text.
pub fn parse_policy(text: &str) -> Result<Policy> {
    // Approval can only be tightened: catch attempts to switch it off.
    let raw: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| anyhow!("policy.yaml is not valid YAML: {e}"))?;
    if let Some(a) = raw.get("approval") {
        for key in ["required", "enabled", "disabled", "auto_approve", "require_approval", "mode"] {
            if a.get(key).is_some() {
                bail!("policy.yaml approval.{key} is not allowed. {APPROVAL_MANDATORY}");
            }
        }
    }
    let p: Policy = serde_yaml::from_value(raw).map_err(|e| anyhow!("policy.yaml: {e}"))?;
    Ok(p)
}

fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host_port = rest.split('/').next()?;
    let host = if host_port.starts_with('[') {
        host_port.split(']').next().map(|h| format!("{h}]"))?
    } else {
        host_port.split(':').next()?.to_string()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Every supported `GOGO_*` variable. Others are rejected (typos fail closed).
pub const KNOWN_VARS: &[&str] = &[
    "GOGO_MODE",
    "GOGO_DATA_DIR",
    "GOGO_CONFIG_DIR",
    "GOGO_HTTP_BIND",
    "GOGO_HTTPS_BIND",
    "GOGO_TLS_CERT_FILE",
    "GOGO_TLS_KEY_FILE",
    "GOGO_PUBLIC_URL",
    "GOGO_ALLOWED_HOSTS",
    "GOGO_TRUST_PROXY",
    "GOGO_LOCAL_ACCOUNTS",
    "GOGO_REQUIRE_TOTP_FOR_LOCAL_ADMINS",
    "GOGO_SESSION_IDLE_HOURS",
    "GOGO_SESSION_MAX_DAYS",
    "GOGO_RECHECK_HOURS",
    "GOGO_AUDIT_RETENTION_DAYS",
    "GOGO_APPROVAL_PENDING_MAX",
    "GOGO_APPROVAL_EXPIRY_DAYS",
    "GOGO_SSO_ENABLED",
    "GOGO_SSO_WELL_KNOWN_URL",
    "GOGO_SSO_CLIENT_ID",
    "GOGO_SSO_CLIENT_SECRET_FILE",
    "GOGO_SSO_USERNAME_CLAIM",
    "GOGO_SSO_GROUPS_CLAIM",
    "GOGO_SSO_SESSION_MAX_HOURS",
    "GOGO_LIBRARIES",
    "GOGO_LIBRARIES_DIR",
    "GOGO_PROFILE",
    "GOGO_LOG",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        let mut m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        m.entry("GOGO_MODE".into()).or_insert("standalone".into());
        m.entry("GOGO_DATA_DIR".into()).or_insert("/tmp/gogo-test".into());
        m
    }

    #[test]
    fn defaults_are_loopback_only() {
        let c = Config::from_map(&map(&[])).unwrap();
        assert_eq!(c.http_bind.unwrap().to_string(), "127.0.0.1:4680");
        assert!(c.https_bind.is_none());
        assert!(!c.require_totp_for_local_admins);
    }

    #[test]
    fn docker_defaults() {
        let c = Config::from_map(&map(&[("GOGO_MODE", "docker"), ("GOGO_CONFIG_DIR", "/nonexistent")])).unwrap();
        assert!(c.http_bind.is_none());
        assert_eq!(c.https_bind.unwrap().to_string(), "0.0.0.0:4681");
        assert!(c.require_totp_for_local_admins, "network-reachable: admin codes required");
    }

    #[test]
    fn refuses_unsafe_or_unknown_settings() {
        for (k, v) in [
            ("GOGO_SSO_REQUIRE_APPROVAL", "false"),
            ("GOGO_SSO_AUTO_APPROVE", "true"),
            ("GOGO_SSO_CLIENT_SECRET", "abc"),
            ("GOGO_HTTP_BIND", "0.0.0.0:4680"),
            ("GOGO_APPROVAL_PENDING_MAX", "501"),
            ("GOGO_APPROVAL_EXPIRY_DAYS", "0"),
            ("GOGO_AUDIT_RETENTION_DAYS", "30"),
            ("GOGO_LOCAL_ACCOUNTS", "nobody"),
            ("GOGO_PUBLIC_URL", "http://nas.local"),
            ("GOGO_HTTPS_BIND_TYPO", "x"),
        ] {
            let err = Config::from_map(&map(&[(k, v)]));
            assert!(err.is_err(), "{k}={v} should be refused");
        }
        let e = Config::from_map(&map(&[("GOGO_SSO_AUTO_APPROVE", "1")])).unwrap_err().to_string();
        assert!(e.contains(APPROVAL_MANDATORY));
        assert!(Config::from_map(&map(&[
            ("GOGO_HTTPS_BIND", "0.0.0.0:4681"),
            ("GOGO_REQUIRE_TOTP_FOR_LOCAL_ADMINS", "false")
        ]))
        .is_err());
    }

    #[test]
    fn http_behind_proxy_allowed_when_trusted() {
        let c = Config::from_map(&map(&[("GOGO_HTTP_BIND", "0.0.0.0:4680"), ("GOGO_TRUST_PROXY", "true")])).unwrap();
        assert!(c.require_totp_for_local_admins);
    }

    #[test]
    fn hosts_from_public_url() {
        let c = Config::from_map(&map(&[
            ("GOGO_PUBLIC_URL", "https://Search.Example.lan:4681/"),
            ("GOGO_ALLOWED_HOSTS", "nas,192.168.1.10"),
        ]))
        .unwrap();
        for h in ["search.example.lan", "nas", "192.168.1.10", "127.0.0.1"] {
            assert!(c.allowed_hosts.contains(&h.to_string()), "{h}");
        }
    }

    #[test]
    fn policy_rules() {
        assert!(parse_policy("approval:\n  required: false\n").is_err());
        assert!(parse_policy("approval:\n  auto_approve: true\n").is_err());
        assert!(parse_policy("sign_in:\n  local_acounts: all\n").is_err(), "typo is refused");
        let p = parse_policy("sign_in:\n  local_accounts: admins_only\napproval:\n  pending_max: 25\n  expiry_days: 14\n  admin_role_requires_two_admins: true\nusers:\n  require_totp_for_local_admins: true\n").unwrap();
        assert_eq!(p.sign_in.unwrap().local_accounts, Some(LocalAccounts::AdminsOnly));
    }

    #[test]
    fn policy_file_tightens_and_locks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("policy.yaml"),
            "sign_in:\n  local_accounts: admins_only\napproval:\n  pending_max: 10\n",
        )
        .unwrap();
        let c = Config::from_map(&map(&[
            ("GOGO_CONFIG_DIR", dir.path().to_str().unwrap()),
            ("GOGO_LOCAL_ACCOUNTS", "all"),
        ]))
        .unwrap();
        assert_eq!(c.local_accounts, LocalAccounts::AdminsOnly);
        assert_eq!(c.approval_pending_max, 10);
        assert!(c.locked.contains(&"sign_in.local_accounts".to_string()));
    }

    #[test]
    fn libraries_env() {
        let libs = parse_libraries("Docs=/home/leo/Documents; Photos=/mnt/photos").unwrap();
        assert_eq!(libs.len(), 2);
        assert!(parse_libraries("Docs=relative/path").is_err());
        assert!(parse_libraries("NoEquals").is_err());
    }
}
