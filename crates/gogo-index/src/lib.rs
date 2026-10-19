//! In-memory file-name index for Gogo Desktop.
//!
//! Every file and folder is a node in a tree per library. Nodes are keyed by a
//! platform file key: the NTFS file reference number on Windows, or the inode on
//! Linux. Renames and moves are therefore cheap updates, and moving a folder
//! moves its whole subtree. Names are matched in memory with a linear scan,
//! split across CPU cores for large indexes.

mod query;

pub use query::{parse_query, Query, QueryError, SizeOp, Term};

use serde::Serialize;
use std::collections::{BinaryHeap, HashMap};

/// Library identifier (one library = one indexed root folder).
pub type LibraryId = u16;

const NONE: u32 = u32::MAX;

/// Basic metadata kept for every entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EntryMeta {
    pub is_dir: bool,
    /// Size in bytes (0 for folders, or when unknown).
    pub size: u64,
    /// Last modified time, Unix seconds (0 when unknown).
    pub mtime: i64,
}

#[derive(Debug)]
struct Node {
    key: u64,
    parent: u32,
    library: LibraryId,
    name: Box<str>,
    lower: Box<str>,
    meta: EntryMeta,
    generation: u32,
    alive: bool,
}

/// Errors from index updates.
#[derive(Debug, PartialEq, Eq)]
pub enum IndexError {
    /// The parent folder isn't in the index (yet).
    MissingParent,
    /// The library has no root node.
    UnknownLibrary,
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndexError::MissingParent => write!(f, "parent folder is not indexed"),
            IndexError::UnknownLibrary => write!(f, "library is not registered"),
        }
    }
}
impl std::error::Error for IndexError {}

/// One search result.
#[derive(Clone, Debug, Serialize)]
pub struct Hit {
    pub library: LibraryId,
    pub key: u64,
    /// Path relative to the library root, using `/` as separator.
    pub rel_path: String,
    pub name: String,
    pub meta: EntryMeta,
    pub score: i64,
}

/// Search output: the best hits plus the total number of matches.
#[derive(Clone, Debug, Serialize)]
pub struct SearchResult {
    pub total: usize,
    pub hits: Vec<Hit>,
}

/// The name index.
#[derive(Default)]
pub struct NameIndex {
    nodes: Vec<Node>,
    free: Vec<u32>,
    by_key: HashMap<(LibraryId, u64), u32>,
    children: HashMap<u32, HashMap<Box<str>, u32>>,
    roots: HashMap<LibraryId, u32>,
    live: usize,
}

impl NameIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live entries, excluding library roots.
    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Number of live entries in one library (excluding its root).
    pub fn library_len(&self, lib: LibraryId) -> usize {
        self.nodes.iter().filter(|n| n.alive && n.library == lib && n.parent != NONE).count()
    }

    /// Registers (or re-registers) a library root with its file key.
    pub fn set_root(&mut self, lib: LibraryId, key: u64) {
        if let Some(&old) = self.roots.get(&lib) {
            if self.nodes[old as usize].key == key {
                return;
            }
            self.remove_library(lib);
        }
        let idx = self.alloc(Node {
            key,
            parent: NONE,
            library: lib,
            name: "".into(),
            lower: "".into(),
            meta: EntryMeta { is_dir: true, size: 0, mtime: 0 },
            generation: 0,
            alive: true,
        });
        self.by_key.insert((lib, key), idx);
        self.roots.insert(lib, idx);
    }

    /// The root key of a library, if registered.
    pub fn root_key(&self, lib: LibraryId) -> Option<u64> {
        self.roots.get(&lib).map(|&i| self.nodes[i as usize].key)
    }

    /// Removes a library and everything in it.
    pub fn remove_library(&mut self, lib: LibraryId) {
        if let Some(root) = self.roots.remove(&lib) {
            let key = self.nodes[root as usize].key;
            self.remove_subtree(root);
            self.by_key.remove(&(lib, key));
        }
    }

    /// Inserts or updates an entry. A changed name or parent is treated as a
    /// rename or move; the entry keeps its children.
    pub fn upsert(
        &mut self,
        lib: LibraryId,
        key: u64,
        parent_key: u64,
        name: &str,
        meta: EntryMeta,
        generation: u32,
    ) -> Result<(), IndexError> {
        if !self.roots.contains_key(&lib) {
            return Err(IndexError::UnknownLibrary);
        }
        let parent = *self.by_key.get(&(lib, parent_key)).ok_or(IndexError::MissingParent)?;
        if let Some(&idx) = self.by_key.get(&(lib, key)) {
            if self.nodes[idx as usize].parent == NONE {
                // Never re-parent a library root.
                return Ok(());
            }
            // Guard against cycles: the new parent must not be inside this node.
            if self.is_ancestor(idx, parent) {
                return Err(IndexError::MissingParent);
            }
            let (old_parent, old_name) = {
                let n = &self.nodes[idx as usize];
                (n.parent, n.name.clone())
            };
            if old_parent != parent || &*old_name != name {
                if let Some(map) = self.children.get_mut(&old_parent) {
                    if map.get(&old_name) == Some(&idx) {
                        map.remove(&old_name);
                    }
                }
                self.replace_child(parent, name, idx);
                let n = &mut self.nodes[idx as usize];
                n.parent = parent;
                n.name = name.into();
                n.lower = name.to_lowercase().into();
            }
            let n = &mut self.nodes[idx as usize];
            n.meta = meta;
            n.generation = generation;
            return Ok(());
        }
        let idx = self.alloc(Node {
            key,
            parent,
            library: lib,
            name: name.into(),
            lower: name.to_lowercase().into(),
            meta,
            generation,
            alive: true,
        });
        self.by_key.insert((lib, key), idx);
        self.replace_child(parent, name, idx);
        self.live += 1;
        Ok(())
    }

    /// Removes an entry and, for folders, everything inside it.
    pub fn remove(&mut self, lib: LibraryId, key: u64) -> bool {
        match self.by_key.get(&(lib, key)) {
            Some(&idx) if self.nodes[idx as usize].parent != NONE => {
                let (parent, name) = {
                    let n = &self.nodes[idx as usize];
                    (n.parent, n.name.clone())
                };
                if let Some(map) = self.children.get_mut(&parent) {
                    if map.get(&name) == Some(&idx) {
                        map.remove(&name);
                    }
                }
                self.remove_subtree(idx);
                true
            }
            _ => false,
        }
    }

    /// Finds the key of an entry from its path components below the library root.
    pub fn lookup_path<S: AsRef<str>>(&self, lib: LibraryId, components: &[S]) -> Option<u64> {
        let mut cur = *self.roots.get(&lib)?;
        for c in components {
            cur = *self.children.get(&cur)?.get(c.as_ref())?;
        }
        Some(self.nodes[cur as usize].key)
    }

    /// Relative path of an entry, `/`-separated.
    pub fn rel_path(&self, lib: LibraryId, key: u64) -> Option<String> {
        let idx = *self.by_key.get(&(lib, key))?;
        Some(self.path_of(idx))
    }

    /// Metadata of an entry.
    pub fn meta(&self, lib: LibraryId, key: u64) -> Option<EntryMeta> {
        let idx = *self.by_key.get(&(lib, key))?;
        Some(self.nodes[idx as usize].meta)
    }

    /// Sets metadata for an existing entry (used when size/time are filled in later).
    pub fn set_meta(&mut self, lib: LibraryId, key: u64, meta: EntryMeta) -> bool {
        match self.by_key.get(&(lib, key)) {
            Some(&idx) => {
                self.nodes[idx as usize].meta = meta;
                true
            }
            None => false,
        }
    }

    /// Keys of entries in `lib` that have no modified time yet (listed without
    /// metadata, for example from the NTFS file table).
    pub fn keys_without_meta(&self, lib: LibraryId) -> Vec<u64> {
        self.nodes
            .iter()
            .filter(|n| n.alive && n.library == lib && n.parent != NONE && n.meta.mtime == 0)
            .map(|n| n.key)
            .collect()
    }

    /// Removes every entry of `lib` whose generation is older than `generation`.
    /// Used after a full re-check: anything not seen again is gone.
    pub fn sweep(&mut self, lib: LibraryId, generation: u32) -> usize {
        let stale: Vec<u64> = self
            .nodes
            .iter()
            .filter(|n| n.alive && n.library == lib && n.parent != NONE && n.generation < generation)
            .map(|n| n.key)
            .collect();
        let mut removed = 0;
        for key in stale {
            if self.by_key.contains_key(&(lib, key)) && self.remove(lib, key) {
                removed += 1;
            }
        }
        removed
    }

    /// Runs a query over the allowed libraries and returns the best `limit` hits.
    pub fn search(&self, q: &Query, allowed: &[LibraryId], limit: usize) -> SearchResult {
        let limit = limit.clamp(1, 1000);
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let n = self.nodes.len();
        let chunks = if n > 200_000 { threads.min(16) } else { 1 };
        let chunk_len = n.div_ceil(chunks.max(1)).max(1);
        let parts: Vec<(usize, Vec<(i64, u32)>)> = if chunks <= 1 {
            vec![self.scan(q, allowed, limit, 0, n)]
        } else {
            std::thread::scope(|s| {
                let handles: Vec<_> = (0..chunks)
                    .map(|c| {
                        let start = c * chunk_len;
                        let end = ((c + 1) * chunk_len).min(n);
                        s.spawn(move || self.scan(q, allowed, limit, start, end))
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().expect("search thread")).collect()
            })
        };
        let mut total = 0;
        let mut all: Vec<(i64, u32)> = Vec::new();
        for (t, v) in parts {
            total += t;
            all.extend(v);
        }
        all.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        all.truncate(limit);
        let hits = all
            .into_iter()
            .map(|(score, idx)| {
                let node = &self.nodes[idx as usize];
                Hit {
                    library: node.library,
                    key: node.key,
                    rel_path: self.path_of(idx),
                    name: node.name.to_string(),
                    meta: node.meta,
                    score,
                }
            })
            .collect();
        SearchResult { total, hits }
    }

    // ---- internals ----

    fn scan(
        &self,
        q: &Query,
        allowed: &[LibraryId],
        limit: usize,
        start: usize,
        end: usize,
    ) -> (usize, Vec<(i64, u32)>) {
        let mut heap: BinaryHeap<std::cmp::Reverse<(i64, std::cmp::Reverse<u32>)>> = BinaryHeap::new();
        let mut total = 0;
        let mut path_buf = String::new();
        let now = unix_now();
        for i in start..end {
            let node = &self.nodes[i];
            if !node.alive || node.parent == NONE || !allowed.contains(&node.library) {
                continue;
            }
            let Some(mut score) = q.match_name(&node.lower, &node.meta) else { continue };
            if q.needs_path() {
                path_buf.clear();
                self.write_lower_path(i as u32, &mut path_buf);
                if !q.match_path(&path_buf) {
                    continue;
                }
            }
            // Small boost for recently changed items and shallow paths.
            score += recency_bonus(node.meta.mtime, now);
            score -= self.depth(i as u32) as i64;
            total += 1;
            let item = std::cmp::Reverse((score, std::cmp::Reverse(i as u32)));
            if heap.len() < limit {
                heap.push(item);
            } else if let Some(top) = heap.peek() {
                if item < *top {
                    heap.pop();
                    heap.push(item);
                }
            }
        }
        let v = heap.into_iter().map(|std::cmp::Reverse((s, std::cmp::Reverse(i)))| (s, i)).collect();
        (total, v)
    }

    fn alloc(&mut self, node: Node) -> u32 {
        if let Some(i) = self.free.pop() {
            self.nodes[i as usize] = node;
            i
        } else {
            self.nodes.push(node);
            (self.nodes.len() - 1) as u32
        }
    }

    fn replace_child(&mut self, parent: u32, name: &str, idx: u32) {
        let map = self.children.entry(parent).or_default();
        if let Some(prev) = map.insert(name.into(), idx) {
            if prev != idx {
                // A different entry had this name: it was replaced on disk.
                self.remove_subtree(prev);
            }
        }
    }

    fn remove_subtree(&mut self, idx: u32) {
        let mut stack = vec![idx];
        while let Some(i) = stack.pop() {
            if let Some(kids) = self.children.remove(&i) {
                stack.extend(kids.into_values());
            }
            let n = &mut self.nodes[i as usize];
            if !n.alive {
                continue;
            }
            let was_entry = n.parent != NONE;
            n.alive = false;
            n.name = "".into();
            n.lower = "".into();
            let key = (n.library, n.key);
            if self.by_key.get(&key) == Some(&i) {
                self.by_key.remove(&key);
            }
            self.free.push(i);
            if was_entry {
                self.live -= 1;
            }
        }
    }

    fn is_ancestor(&self, ancestor: u32, mut idx: u32) -> bool {
        loop {
            if idx == ancestor {
                return true;
            }
            let p = self.nodes[idx as usize].parent;
            if p == NONE {
                return false;
            }
            idx = p;
        }
    }

    fn depth(&self, mut idx: u32) -> usize {
        let mut d = 0;
        while self.nodes[idx as usize].parent != NONE {
            idx = self.nodes[idx as usize].parent;
            d += 1;
        }
        d
    }

    fn path_of(&self, idx: u32) -> String {
        let mut parts = Vec::new();
        let mut cur = idx;
        while self.nodes[cur as usize].parent != NONE {
            parts.push(&*self.nodes[cur as usize].name);
            cur = self.nodes[cur as usize].parent;
        }
        parts.reverse();
        parts.join("/")
    }

    fn write_lower_path(&self, idx: u32, out: &mut String) {
        let mut parts = Vec::new();
        let mut cur = idx;
        while self.nodes[cur as usize].parent != NONE {
            parts.push(&*self.nodes[cur as usize].lower);
            cur = self.nodes[cur as usize].parent;
        }
        for (i, p) in parts.iter().rev().enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(p);
        }
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn recency_bonus(mtime: i64, now: i64) -> i64 {
    if mtime <= 0 {
        return 0;
    }
    let age_days = (now - mtime).max(0) / 86_400;
    match age_days {
        0..=1 => 30,
        2..=7 => 20,
        8..=30 => 10,
        31..=365 => 3,
        _ => 0,
    }
}

#[cfg(test)]
mod tests;
