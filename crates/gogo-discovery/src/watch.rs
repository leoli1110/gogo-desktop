//! Live change tracking with file notifications (inotify / ReadDirectoryChangesW),
//! plus scheduled re-checks as a safety net.

use crate::scan::{file_key, is_excluded, meta_of, scan_subtree};
use crate::{full_scan, Ctx, LibraryState, WatchMethod};
use notify::{RecursiveMode, Watcher};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Extra watches to leave free for other programs on the NAS.
const WATCH_MARGIN: usize = 1024;

pub(crate) fn inotify_limit() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches").ok()?.trim().parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn native_method() -> WatchMethod {
    if cfg!(target_os = "linux") {
        WatchMethod::Inotify
    } else if cfg!(windows) {
        WatchMethod::ReadDirectoryChanges
    } else {
        WatchMethod::Notifications
    }
}

pub(crate) fn run_generic(ctx: &Ctx) {
    let mut generation: u32 = 1;
    let stats = full_scan(ctx, generation);
    if ctx.stopped() {
        ctx.set(|s| s.state = LibraryState::Stopped);
        return;
    }
    let needed = stats.folders + 1;
    let limit = inotify_limit();
    ctx.set(|s| {
        s.watches_needed = needed;
        s.watch_limit = limit;
    });

    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut _watcher: Option<notify::RecommendedWatcher> = None;
    let enough_watches = limit.map(|l| needed + WATCH_MARGIN <= l).unwrap_or(true);
    if !enough_watches {
        let msg = format!(
            "needs about {needed} folder watches but the system limit is {}; using scheduled re-checks only. \
             Raise fs.inotify.max_user_watches on the NAS (see docs/install-synology.md).",
            limit.unwrap_or(0)
        );
        tracing::warn!(library = %ctx.spec.name, "{msg}");
        ctx.set(|s| {
            s.method = WatchMethod::RecheckOnly;
            s.message = Some(msg);
        });
    } else {
        match notify::recommended_watcher(tx).and_then(|mut w| {
            w.watch(&ctx.spec.root, RecursiveMode::Recursive)?;
            Ok(w)
        }) {
            Ok(w) => {
                _watcher = Some(w);
                ctx.set(|s| s.method = native_method());
            }
            Err(e) => {
                let msg = format!("file notifications unavailable ({e}); using scheduled re-checks only");
                tracing::warn!(library = %ctx.spec.name, "{msg}");
                ctx.set(|s| {
                    s.method = WatchMethod::RecheckOnly;
                    s.message = Some(msg);
                });
            }
        }
    }
    ctx.set(|s| s.state = LibraryState::Watching);

    let mut next_recheck = Instant::now() + ctx.opts.recheck_interval;
    let mut pending: BTreeSet<PathBuf> = BTreeSet::new();
    let mut overflow = false;
    while !ctx.stopped() {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(ev) => {
                absorb(ev, &mut pending, &mut overflow);
                // Collect a short burst so renames arrive together.
                let burst_end = Instant::now() + Duration::from_millis(150);
                while let Ok(ev) = rx.recv_timeout(burst_end.saturating_duration_since(Instant::now())) {
                    absorb(ev, &mut pending, &mut overflow);
                    if pending.len() > 20_000 {
                        overflow = true;
                        break;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Watcher gone: keep re-checks running.
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        if !pending.is_empty() && !overflow {
            let paths: Vec<PathBuf> = std::mem::take(&mut pending).into_iter().collect();
            apply_changes(ctx, &paths, generation);
            let n = ctx.index.read().library_len(ctx.spec.id);
            ctx.set(|s| s.entries = n);
        }
        if overflow || ctx.take_recheck() || Instant::now() >= next_recheck {
            if overflow {
                tracing::warn!(library = %ctx.spec.name, "change notifications overflowed; re-checking");
            }
            pending.clear();
            overflow = false;
            generation = generation.wrapping_add(1).max(1);
            full_scan(ctx, generation);
            next_recheck = Instant::now() + ctx.opts.recheck_interval;
            ctx.set(|s| s.state = LibraryState::Watching);
        }
    }
    ctx.set(|s| s.state = LibraryState::Stopped);
}

fn absorb(ev: notify::Result<notify::Event>, pending: &mut BTreeSet<PathBuf>, overflow: &mut bool) {
    match ev {
        Ok(ev) => {
            if ev.need_rescan() {
                *overflow = true;
            }
            pending.extend(ev.paths);
        }
        Err(_) => *overflow = true,
    }
}

fn components(rel: &Path) -> Vec<String> {
    rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect()
}

/// Applies a batch of changed paths. Paths that still exist are added or
/// updated first (parents before children), so a rename is seen as a move of
/// the existing entry; then paths that no longer exist are removed.
pub(crate) fn apply_changes(ctx: &Ctx, paths: &[PathBuf], generation: u32) {
    let spec = &ctx.spec;
    let mut existing: Vec<(PathBuf, std::fs::Metadata)> = Vec::new();
    let mut missing: Vec<PathBuf> = Vec::new();
    for p in paths {
        let Ok(rel) = p.strip_prefix(&spec.root) else { continue };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let excluded = rel.components().any(|c| {
            let name = c.as_os_str().to_string_lossy();
            is_excluded(&name, p, spec, &ctx.opts)
        });
        if excluded {
            continue;
        }
        match std::fs::symlink_metadata(p) {
            Ok(m) => existing.push((p.clone(), m)),
            Err(_) => missing.push(p.clone()),
        }
    }
    existing.sort_by_key(|(p, _)| p.components().count());
    for (path, m) in existing {
        let rel = path.strip_prefix(&spec.root).expect("checked above");
        let comps = components(rel);
        let (parent_comps, name) = comps.split_at(comps.len() - 1);
        let parent_key = ctx.index.read().lookup_path(spec.id, parent_comps);
        let Some(parent_key) = parent_key else {
            // Parent not indexed yet (a folder appeared with contents): scan
            // from the highest missing ancestor.
            scan_missing_ancestor(ctx, rel, generation);
            continue;
        };
        let key = file_key(&m, rel);
        let meta = meta_of(&m);
        let known = ctx.index.read().meta(spec.id, key).is_some();
        if meta.is_dir && !known {
            scan_subtree(&ctx.index, spec, &ctx.opts, &path, generation, &ctx.stop);
        } else {
            let _ = ctx.index.write().upsert(spec.id, key, parent_key, &name[0], meta, generation);
        }
    }
    for path in missing {
        let rel = path.strip_prefix(&spec.root).expect("checked above");
        let comps = components(rel);
        let mut ix = ctx.index.write();
        if let Some(key) = ix.lookup_path(spec.id, &comps) {
            ix.remove(spec.id, key);
        }
    }
}

fn scan_missing_ancestor(ctx: &Ctx, rel: &Path, generation: u32) {
    let comps = components(rel);
    for depth in 1..=comps.len() {
        let parent_known = ctx.index.read().lookup_path(ctx.spec.id, &comps[..depth - 1]).is_some();
        let self_known = ctx.index.read().lookup_path(ctx.spec.id, &comps[..depth]).is_some();
        if parent_known && !self_known {
            let mut start = ctx.spec.root.clone();
            for c in &comps[..depth] {
                start.push(c);
            }
            if start.exists() {
                scan_subtree(&ctx.index, &ctx.spec, &ctx.opts, &start, generation, &ctx.stop);
            }
            return;
        }
    }
}
