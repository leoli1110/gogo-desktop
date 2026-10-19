//! File discovery and change tracking.
//!
//! * Windows NTFS volumes: the file table is listed through the change journal
//!   (`FSCTL_ENUM_USN_DATA`) and followed live (`FSCTL_READ_USN_JOURNAL`).
//! * Everything else (Linux/Synology shares, FAT/exFAT, network drives): a
//!   directory walk plus file notifications (inotify on Linux,
//!   `ReadDirectoryChangesW` on Windows), with a periodic re-check.
//!
//! Each library runs on its own thread and writes into the shared name index.

#[cfg(windows)]
pub mod ntfs;
mod scan;
mod watch;

pub use scan::{default_excludes, file_key, scan_tree, ScanStats};

use gogo_index::{LibraryId, NameIndex};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Index shared between discovery threads and the search API.
pub type SharedIndex = Arc<RwLock<NameIndex>>;

/// What to index for one library.
#[derive(Clone, Debug)]
pub struct LibrarySpec {
    pub id: LibraryId,
    pub name: String,
    pub root: PathBuf,
    /// Extra name patterns to skip (wildcards), on top of the defaults.
    pub excludes: Vec<String>,
}

/// Discovery options shared by all libraries.
#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    /// Full re-check interval (safety net for missed notifications).
    pub recheck_interval: Duration,
    /// Folders that must never be indexed (for example Gogo Desktop's data folder).
    pub never_index: Vec<PathBuf>,
    /// Use the NTFS change journal when possible (Windows only).
    pub use_ntfs_journal: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self { recheck_interval: Duration::from_secs(6 * 3600), never_index: Vec::new(), use_ntfs_journal: true }
    }
}

/// How changes are being tracked for a library.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchMethod {
    None,
    NtfsJournal,
    Inotify,
    ReadDirectoryChanges,
    Notifications,
    /// Not enough inotify watches: only scheduled re-checks.
    RecheckOnly,
}

/// Library state shown on the status page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LibraryState {
    Starting,
    Scanning,
    Watching,
    Error,
    Stopped,
}

/// Status for one library.
#[derive(Clone, Debug, Serialize)]
pub struct LibraryStatus {
    pub id: LibraryId,
    pub name: String,
    pub state: LibraryState,
    pub method: WatchMethod,
    pub entries: usize,
    pub folders: usize,
    pub errors: usize,
    pub last_scan_ms: u64,
    pub last_scan_at: i64,
    pub next_recheck_at: i64,
    pub watches_needed: usize,
    pub watch_limit: Option<usize>,
    pub message: Option<String>,
}

/// A running library: its thread, status and stop flag.
pub struct LibraryHandle {
    pub spec: LibrarySpec,
    status: Arc<Mutex<LibraryStatus>>,
    stop: Arc<AtomicBool>,
    recheck: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LibraryHandle {
    pub fn status(&self) -> LibraryStatus {
        self.status.lock().clone()
    }

    /// Asks for a full re-check as soon as possible.
    pub fn request_recheck(&self) {
        self.recheck.store(true, Ordering::SeqCst);
    }

    /// Stops the library thread and removes its entries from the index.
    pub fn stop(mut self, index: &SharedIndex) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        index.write().remove_library(self.spec.id);
    }
}

impl Drop for LibraryHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Shared state passed to the per-library worker.
pub(crate) struct Ctx {
    pub spec: LibrarySpec,
    pub index: SharedIndex,
    pub opts: DiscoveryOptions,
    pub status: Arc<Mutex<LibraryStatus>>,
    pub stop: Arc<AtomicBool>,
    pub recheck: Arc<AtomicBool>,
}

impl Ctx {
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
    pub fn set<F: FnOnce(&mut LibraryStatus)>(&self, f: F) {
        f(&mut self.status.lock());
    }
    pub fn take_recheck(&self) -> bool {
        self.recheck.swap(false, Ordering::SeqCst)
    }
}

/// Starts indexing and watching a library on a background thread.
pub fn start_library(spec: LibrarySpec, index: SharedIndex, opts: DiscoveryOptions) -> LibraryHandle {
    let status = Arc::new(Mutex::new(LibraryStatus {
        id: spec.id,
        name: spec.name.clone(),
        state: LibraryState::Starting,
        method: WatchMethod::None,
        entries: 0,
        folders: 0,
        errors: 0,
        last_scan_ms: 0,
        last_scan_at: 0,
        next_recheck_at: 0,
        watches_needed: 0,
        watch_limit: None,
        message: None,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let recheck = Arc::new(AtomicBool::new(false));
    let ctx =
        Ctx { spec: spec.clone(), index, opts, status: status.clone(), stop: stop.clone(), recheck: recheck.clone() };
    let thread = std::thread::Builder::new()
        .name(format!("library-{}", spec.id))
        .spawn(move || run_library(ctx))
        .expect("spawn library thread");
    LibraryHandle { spec, status, stop, recheck, thread: Some(thread) }
}

fn run_library(ctx: Ctx) {
    if !ctx.spec.root.is_dir() {
        ctx.set(|s| {
            s.state = LibraryState::Error;
            s.message = Some(format!("folder not found: {}", ctx.spec.root.display()));
        });
        return;
    }
    #[cfg(windows)]
    if ctx.opts.use_ntfs_journal {
        match ntfs::run(&ctx) {
            Ok(()) => return,
            Err(e) => {
                tracing::info!(library = %ctx.spec.name, "NTFS journal not used ({e}); using folder scan");
            }
        }
    }
    watch::run_generic(&ctx);
}

/// Runs a full scan with a new generation and removes anything not seen.
pub(crate) fn full_scan(ctx: &Ctx, generation: u32) -> ScanStats {
    ctx.set(|s| s.state = LibraryState::Scanning);
    let started = Instant::now();
    let stats = scan_tree(&ctx.index, &ctx.spec, &ctx.opts, generation, &ctx.stop);
    let removed = ctx.index.write().sweep(ctx.spec.id, generation);
    let elapsed = started.elapsed().as_millis() as u64;
    let entries = ctx.index.read().library_len(ctx.spec.id);
    tracing::info!(
        library = %ctx.spec.name,
        entries,
        folders = stats.folders,
        removed,
        ms = elapsed,
        "scan finished"
    );
    ctx.set(|s| {
        s.entries = entries;
        s.folders = stats.folders;
        s.errors = stats.errors;
        s.last_scan_ms = elapsed;
        s.last_scan_at = unix_now();
        s.next_recheck_at = unix_now() + ctx.opts.recheck_interval.as_secs() as i64;
    });
    stats
}

#[cfg(test)]
mod tests;
