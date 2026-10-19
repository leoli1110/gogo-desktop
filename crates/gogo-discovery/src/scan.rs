//! Directory walk used for Linux/Synology shares and as the Windows fallback.

use crate::{DiscoveryOptions, LibrarySpec, SharedIndex};
use gogo_index::EntryMeta;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

/// Result of a scan.
#[derive(Clone, Debug, Default)]
pub struct ScanStats {
    pub files: usize,
    pub folders: usize,
    pub errors: usize,
}

/// Names skipped everywhere: Synology system folders, Windows system folders.
pub fn default_excludes() -> Vec<String> {
    [
        "#recycle",
        "@eaDir",
        "#snapshot",
        "@tmp",
        ".SynologyWorkingDirectory",
        "$Recycle.Bin",
        "System Volume Information",
        "$RECYCLE.BIN",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Stable key for a file. On Unix this is the inode (scans stay on one file
/// system), so renames keep their key. Elsewhere it's a hash of the path
/// below the library root.
pub fn file_key(meta: &Metadata, rel: &Path) -> u64 {
    #[cfg(unix)]
    {
        let _ = rel;
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        path_hash(rel)
    }
}

/// FNV-1a hash of a lowercased relative path (Windows fallback keys).
#[cfg_attr(unix, allow(dead_code))]
pub(crate) fn path_hash(rel: &Path) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in rel.to_string_lossy().to_lowercase().replace('\\', "/").bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    // Keep 0 free for "root" in fallback mode.
    h | 1
}

pub(crate) fn meta_of(m: &Metadata) -> EntryMeta {
    let mtime =
        m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
    EntryMeta { is_dir: m.is_dir(), size: if m.is_dir() { 0 } else { m.len() }, mtime }
}

pub(crate) fn is_excluded(name: &str, path: &Path, spec: &LibrarySpec, opts: &DiscoveryOptions) -> bool {
    if default_excludes().iter().any(|e| e.eq_ignore_ascii_case(name)) {
        return true;
    }
    if spec.excludes.iter().any(|p| wildcard(&p.to_lowercase(), &name.to_lowercase())) {
        return true;
    }
    opts.never_index.iter().any(|n| path.starts_with(n))
}

fn wildcard(p: &str, t: &str) -> bool {
    let p: Vec<char> = p.chars().collect();
    let t: Vec<char> = t.chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None::<usize>, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Root key of a library folder.
pub(crate) fn root_key(root: &Path) -> std::io::Result<u64> {
    let m = std::fs::symlink_metadata(root)?;
    #[cfg(unix)]
    {
        Ok(file_key(&m, Path::new("")))
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        Ok(0)
    }
}

/// Walks `start` (the library root or a folder inside it) and upserts every
/// entry with `generation`. Symbolic links are recorded but never followed,
/// and the walk never leaves the library's file system.
pub(crate) fn scan_subtree(
    index: &SharedIndex,
    spec: &LibrarySpec,
    opts: &DiscoveryOptions,
    start: &Path,
    generation: u32,
    stop: &AtomicBool,
) -> ScanStats {
    let mut stats = ScanStats::default();
    let mut batch: Vec<(u64, u64, String, EntryMeta)> = Vec::with_capacity(4096);
    let walker = walkdir::WalkDir::new(start)
        .follow_links(false)
        .same_file_system(true)
        .min_depth(if start == spec.root { 1 } else { 0 })
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !is_excluded(&e.file_name().to_string_lossy(), e.path(), spec, opts));
    // Map from path to key for parents seen in this walk (walk is pre-order).
    let mut parent_keys: std::collections::HashMap<PathBuf, u64> = std::collections::HashMap::new();
    let root_key = match root_key(&spec.root) {
        Ok(k) => k,
        Err(_) => {
            stats.errors += 1;
            return stats;
        }
    };
    parent_keys.insert(spec.root.clone(), root_key);
    for entry in walker {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(&spec.root) else { continue };
        let m = match entry.metadata() {
            Ok(m) => m,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        let key = file_key(&m, rel);
        let Some(parent_path) = path.parent() else { continue };
        let parent_key = match parent_keys.get(parent_path) {
            Some(k) => *k,
            None => {
                // Starting inside the library: resolve the parent from the index.
                let comps: Vec<String> = parent_path
                    .strip_prefix(&spec.root)
                    .map(|p| p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect())
                    .unwrap_or_default();
                match index.read().lookup_path(spec.id, &comps) {
                    Some(k) => k,
                    None => {
                        stats.errors += 1;
                        continue;
                    }
                }
            }
        };
        let meta = meta_of(&m);
        if meta.is_dir {
            stats.folders += 1;
            parent_keys.insert(path.to_path_buf(), key);
        } else {
            stats.files += 1;
        }
        batch.push((key, parent_key, entry.file_name().to_string_lossy().into_owned(), meta));
        if batch.len() >= 4096 {
            flush(index, spec, &mut batch, generation, &mut stats);
        }
    }
    flush(index, spec, &mut batch, generation, &mut stats);
    stats
}

fn flush(
    index: &SharedIndex,
    spec: &LibrarySpec,
    batch: &mut Vec<(u64, u64, String, EntryMeta)>,
    generation: u32,
    stats: &mut ScanStats,
) {
    if batch.is_empty() {
        return;
    }
    let mut ix = index.write();
    for (key, parent, name, meta) in batch.drain(..) {
        if ix.upsert(spec.id, key, parent, &name, meta, generation).is_err() {
            stats.errors += 1;
        }
    }
}

/// Scans a whole library (registering its root first).
pub fn scan_tree(
    index: &SharedIndex,
    spec: &LibrarySpec,
    opts: &DiscoveryOptions,
    generation: u32,
    stop: &AtomicBool,
) -> ScanStats {
    match root_key(&spec.root) {
        Ok(k) => index.write().set_root(spec.id, k),
        Err(_) => return ScanStats { errors: 1, ..Default::default() },
    }
    scan_subtree(index, spec, opts, &spec.root, generation, stop)
}
