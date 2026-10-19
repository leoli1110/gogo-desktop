//! Shared application state.

use crate::config::{Config, Mode};
use gogo_auth::audit::AuditLog;
use gogo_auth::{normalize_code, now, random_code, random_token, sha256_hex, Library, SessionPolicy, Store};
use gogo_discovery::{start_library, DiscoveryOptions, LibraryHandle, LibrarySpec, LibraryStatus, SharedIndex};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// First-run setup state: a one-time code printed in the log.
pub struct Setup {
    pub code_hash: String,
    pub totp_secret: Option<String>,
}

/// In-memory fixed-window rate limiter.
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<(String, IpAddr), (i64, u32)>>,
}

impl RateLimiter {
    /// Returns true if the action is allowed (max `limit` per `window_secs`).
    pub fn allow(&self, bucket: &str, ip: IpAddr, limit: u32, window_secs: i64) -> bool {
        let t = now();
        let mut w = self.windows.lock();
        if w.len() > 10_000 {
            w.retain(|_, (start, _)| t - *start < window_secs);
        }
        let e = w.entry((bucket.to_string(), ip)).or_insert((t, 0));
        if t - e.0 >= window_secs {
            *e = (t, 0);
        }
        e.1 += 1;
        e.1 <= limit
    }
}

pub struct AppState {
    pub cfg: Config,
    pub store: Store,
    pub audit: AuditLog,
    pub index: SharedIndex,
    pub libraries: Mutex<HashMap<i64, LibraryHandle>>,
    pub setup: Mutex<Option<Setup>>,
    /// One-time sign-in tokens (same-PC Windows sign-in): hash -> (user id, expiry).
    pub onetime: Mutex<HashMap<String, (i64, i64)>>,
    pub rate: RateLimiter,
    pub started: Instant,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(cfg: Config) -> anyhow::Result<Shared> {
        let store = Store::open(&cfg.db_path())?;
        let audit = AuditLog::open(&cfg.audit_dir())?;
        let state = Arc::new(AppState {
            cfg,
            store,
            audit,
            index: SharedIndex::default(),
            libraries: Mutex::new(HashMap::new()),
            setup: Mutex::new(None),
            onetime: Mutex::new(HashMap::new()),
            rate: RateLimiter::default(),
            started: Instant::now(),
        });
        state.ensure_setup_code()?;
        Ok(state)
    }

    pub fn session_policy(&self) -> SessionPolicy {
        SessionPolicy {
            idle_secs: self.cfg.session_idle.as_secs() as i64,
            absolute_secs: self.cfg.session_max.as_secs() as i64,
        }
    }

    /// If no Gogo Desktop administrator exists, enters setup mode and prints a code.
    pub fn ensure_setup_code(&self) -> anyhow::Result<()> {
        if self.store.local_admin_count()? > 0 {
            self.finish_setup();
            return Ok(());
        }
        let code = random_code();
        *self.setup.lock() = Some(Setup { code_hash: sha256_hex(normalize_code(&code).as_bytes()), totp_secret: None });
        let url = self
            .cfg
            .public_url
            .clone()
            .or_else(|| self.cfg.http_bind.map(|a| format!("http://127.0.0.1:{}", a.port())))
            .or_else(|| self.cfg.https_bind.map(|a| format!("https://<this-nas>:{}", a.port())))
            .unwrap_or_default();
        let banner = format!(
            "\n==================== Gogo Desktop setup ====================\n\
             No administrator account exists yet.\n\
             Open {url}/setup and enter this one-time setup code:\n\n    {code}\n\n\
             The code is valid until an administrator is created.\n\
             ============================================================"
        );
        // Printed to the console/container log on purpose: it's how the owner proves access.
        eprintln!("{banner}");
        // Also saved in the data folder (readable only by administrators/the service account),
        // because a Windows service has no console.
        let file = self.cfg.data_dir.join("setup-code.txt");
        if let Err(e) = std::fs::write(&file, format!("{code}\n")) {
            tracing::warn!("can't save {}: {e}", file.display());
        }
        tracing::warn!("setup required: no administrator account exists (see the setup code above)");
        Ok(())
    }

    /// Leaves setup mode and removes the saved setup code.
    pub fn finish_setup(&self) {
        *self.setup.lock() = None;
        let _ = std::fs::remove_file(self.cfg.data_dir.join("setup-code.txt"));
    }

    pub fn setup_required(&self) -> bool {
        self.setup.lock().is_some()
    }

    /// Issues a one-time sign-in token for a user (valid 60 seconds).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn issue_onetime(&self, user_id: i64) -> String {
        let token = random_token(32);
        let mut m = self.onetime.lock();
        let t = now();
        m.retain(|_, (_, exp)| *exp > t);
        m.insert(sha256_hex(token.as_bytes()), (user_id, t + 60));
        token
    }

    /// Uses a one-time token. Single use.
    pub fn take_onetime(&self, token: &str) -> Option<i64> {
        let mut m = self.onetime.lock();
        let (uid, exp) = m.remove(&sha256_hex(token.as_bytes()))?;
        (exp > now()).then_some(uid)
    }

    fn discovery_options(&self) -> DiscoveryOptions {
        DiscoveryOptions {
            recheck_interval: self.cfg.recheck_interval,
            never_index: vec![self.cfg.data_dir.clone()],
            use_ntfs_journal: true,
        }
    }

    /// Registers libraries from configuration (container mounts, GOGO_LIBRARIES).
    pub fn register_config_libraries(&self) -> anyhow::Result<()> {
        let existing = self.store.list_libraries()?;
        for cl in &self.cfg.libraries {
            let path = cl.path.to_string_lossy().to_string();
            if existing.iter().any(|l| l.name.eq_ignore_ascii_case(&cl.name)) {
                continue;
            }
            match self.store.add_library(&cl.name, &path, None, "config") {
                Ok(l) => {
                    tracing::info!(library = %l.name, path = %l.path, "library registered from configuration");
                    self.audit.record(
                        "library.registered",
                        Some("configuration"),
                        None,
                        serde_json::json!({ "library": l.name, "path": l.path }),
                    );
                }
                Err(e) => tracing::warn!(library = %cl.name, "can't register library: {e}"),
            }
        }
        Ok(())
    }

    /// Starts discovery for every library that isn't running yet.
    pub fn start_libraries(&self) -> anyhow::Result<()> {
        let libs = self.store.list_libraries()?;
        let mut running = self.libraries.lock();
        for l in libs {
            if running.contains_key(&l.id) {
                continue;
            }
            running.insert(l.id, self.spawn_library(&l));
        }
        Ok(())
    }

    fn spawn_library(&self, l: &Library) -> LibraryHandle {
        let spec = LibrarySpec {
            id: l.id as u16,
            name: l.name.clone(),
            root: PathBuf::from(&l.path),
            excludes: l.excludes.clone(),
        };
        start_library(spec, self.index.clone(), self.discovery_options())
    }

    /// Restarts one library (after its settings changed).
    pub fn restart_library(&self, id: i64) -> anyhow::Result<()> {
        let old = self.libraries.lock().remove(&id);
        if let Some(h) = old {
            h.stop(&self.index);
        }
        let l = self.store.library(id)?;
        let h = self.spawn_library(&l);
        self.libraries.lock().insert(id, h);
        Ok(())
    }

    pub fn stop_library(&self, id: i64) {
        let old = self.libraries.lock().remove(&id);
        if let Some(h) = old {
            h.stop(&self.index);
        }
    }

    pub fn library_status(&self) -> Vec<LibraryStatus> {
        let mut v: Vec<LibraryStatus> = self.libraries.lock().values().map(|h| h.status()).collect();
        v.sort_by_key(|a| a.name.to_lowercase());
        v
    }

    pub fn request_recheck(&self, id: i64) -> bool {
        match self.libraries.lock().get(&id) {
            Some(h) => {
                h.request_recheck();
                true
            }
            None => false,
        }
    }

    /// Display path for a hit: the library's display prefix (for example
    /// `\\NAS\Projects`) or its folder, plus the relative path.
    pub fn display_path(&self, lib: &Library, rel: &str) -> String {
        let base = lib.display_prefix.clone().unwrap_or_else(|| lib.path.clone());
        let sep = if base.contains('\\') || (self.cfg.mode == Mode::Windows && lib.display_prefix.is_none()) {
            '\\'
        } else {
            '/'
        };
        let base = base.trim_end_matches(['\\', '/']);
        if rel.is_empty() {
            return base.to_string();
        }
        let rel = if sep == '\\' { rel.replace('/', "\\") } else { rel.to_string() };
        format!("{base}{sep}{rel}")
    }
}
