//! Append-only audit log with a hash chain (spec section 3.3.6).
//!
//! One JSON record per line in monthly files `audit-YYYY-MM.jsonl`. Each record
//! stores the hash of the previous record, so edits or deletions inside the
//! kept files are detected by [`verify`].

use crate::sha256_hex;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub ts: i64,
    pub event: String,
    pub actor: Option<String>,
    pub ip: Option<String>,
    pub details: serde_json::Value,
    pub prev: String,
    #[serde(default)]
    pub hash: String,
}

impl Record {
    fn compute_hash(&self) -> String {
        let mut copy = self.clone();
        copy.hash = String::new();
        let body = serde_json::to_string(&copy).expect("audit record serializes");
        sha256_hex(body.as_bytes())
    }
}

struct State {
    seq: u64,
    prev: String,
}

/// The audit log writer.
pub struct AuditLog {
    dir: PathBuf,
    state: Mutex<State>,
}

/// Verification failure.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("{file}: line {line}: {reason}")]
    Broken { file: String, line: usize, reason: String },
    #[error("can't read the audit log: {0}")]
    Io(#[from] std::io::Error),
}

fn civil(ts: i64) -> (i64, u32) {
    // Days to (year, month), H. Hinnant's algorithm.
    let z = ts.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m)
}

fn files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("audit-") && n.ends_with(".jsonl"))
                .unwrap_or(false)
        })
        .collect();
    v.sort();
    Ok(v)
}

impl AuditLog {
    /// Opens the log directory and continues the chain from the last record.
    pub fn open(dir: &Path) -> std::io::Result<AuditLog> {
        fs::create_dir_all(dir)?;
        let mut state = State { seq: 0, prev: GENESIS.to_string() };
        if let Some(last_file) = files(dir)?.last() {
            let reader = BufReader::new(File::open(last_file)?);
            let mut last: Option<Record> = None;
            for line in reader.lines() {
                let line = line?;
                if let Ok(r) = serde_json::from_str::<Record>(&line) {
                    last = Some(r);
                }
            }
            if let Some(r) = last {
                state = State { seq: r.seq, prev: r.hash };
            }
        }
        Ok(AuditLog { dir: dir.to_path_buf(), state: Mutex::new(state) })
    }

    /// Appends a record. Failures are logged but never stop the request.
    pub fn record(&self, event: &str, actor: Option<&str>, ip: Option<&str>, details: serde_json::Value) {
        if let Err(e) = self.try_record(event, actor, ip, details) {
            tracing::error!("audit log write failed: {e}");
        }
    }

    fn try_record(
        &self,
        event: &str,
        actor: Option<&str>,
        ip: Option<&str>,
        details: serde_json::Value,
    ) -> std::io::Result<()> {
        let mut st = self.state.lock();
        let ts = crate::now();
        let mut r = Record {
            seq: st.seq + 1,
            ts,
            event: event.to_string(),
            actor: actor.map(str::to_string),
            ip: ip.map(str::to_string),
            details,
            prev: st.prev.clone(),
            hash: String::new(),
        };
        r.hash = r.compute_hash();
        let (y, m) = civil(ts);
        let path = self.dir.join(format!("audit-{y:04}-{m:02}.jsonl"));
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{}", serde_json::to_string(&r)?)?;
        f.sync_data()?;
        st.seq = r.seq;
        st.prev = r.hash;
        Ok(())
    }

    /// Last `n` records, newest last, optionally only events starting with `prefix`.
    pub fn tail(&self, n: usize, prefix: Option<&str>) -> std::io::Result<Vec<Record>> {
        let mut out: Vec<Record> = Vec::new();
        for f in files(&self.dir)?.iter().rev() {
            let mut recs: Vec<Record> = BufReader::new(File::open(f)?)
                .lines()
                .map_while(Result::ok)
                .filter_map(|l| serde_json::from_str(&l).ok())
                .filter(|r: &Record| prefix.map(|p| r.event.starts_with(p)).unwrap_or(true))
                .collect();
            recs.append(&mut out);
            out = recs;
            if out.len() >= n {
                break;
            }
        }
        let skip = out.len().saturating_sub(n);
        Ok(out.split_off(skip))
    }

    /// Deletes monthly files older than `days` and records that it did.
    pub fn apply_retention(&self, days: i64) -> std::io::Result<usize> {
        let cutoff = crate::now() - days * 86_400;
        let (cy, cm) = civil(cutoff);
        let cutoff_name = format!("audit-{cy:04}-{cm:02}.jsonl");
        let mut removed = Vec::new();
        for f in files(&self.dir)? {
            let name = f.file_name().unwrap().to_string_lossy().to_string();
            if name < cutoff_name {
                fs::remove_file(&f)?;
                removed.push(name);
            }
        }
        if !removed.is_empty() {
            self.record("audit.retention", None, None, serde_json::json!({ "removed_files": removed }));
        }
        Ok(removed.len())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Checks every kept record and the links between them. Returns the number of
/// records checked. The first kept record may follow removed (expired) files.
pub fn verify(dir: &Path) -> Result<usize, VerifyError> {
    let mut prev: Option<String> = None;
    let mut prev_seq: Option<u64> = None;
    let mut count = 0;
    for f in files(dir)? {
        let fname = f.file_name().unwrap().to_string_lossy().to_string();
        for (i, line) in BufReader::new(File::open(&f)?).lines().enumerate() {
            let line = line?;
            let broken = |reason: &str| VerifyError::Broken { file: fname.clone(), line: i + 1, reason: reason.into() };
            let r: Record = serde_json::from_str(&line).map_err(|_| broken("not a valid record"))?;
            if r.compute_hash() != r.hash {
                return Err(broken("record was changed (hash mismatch)"));
            }
            if let Some(p) = &prev {
                if &r.prev != p {
                    return Err(broken("chain broken: a record before this one was changed or removed"));
                }
            }
            if let Some(s) = prev_seq {
                if r.seq != s + 1 {
                    return Err(broken("sequence gap: records are missing"));
                }
            }
            prev = Some(r.hash.clone());
            prev_seq = Some(r.seq);
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..5 {
            log.record("user.created", Some("admin"), Some("127.0.0.1"), serde_json::json!({ "n": i }));
        }
        assert_eq!(verify(dir.path()).unwrap(), 5);
        // Reopening continues the chain.
        drop(log);
        let log = AuditLog::open(dir.path()).unwrap();
        log.record("user.deleted", Some("admin"), None, serde_json::json!({}));
        assert_eq!(verify(dir.path()).unwrap(), 6);
        assert_eq!(log.tail(2, None).unwrap().len(), 2);
        assert_eq!(log.tail(10, Some("user.deleted")).unwrap().len(), 1);

        let f = files(dir.path()).unwrap().pop().unwrap();
        let text = fs::read_to_string(&f).unwrap();
        // Edit a record.
        fs::write(&f, text.replacen("\"n\":2", "\"n\":9", 1)).unwrap();
        assert!(matches!(verify(dir.path()), Err(VerifyError::Broken { line: 3, .. })));
        // Delete a record.
        let lines: Vec<&str> = text.lines().collect();
        let without: String =
            lines.iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| format!("{l}\n")).collect();
        fs::write(&f, without).unwrap();
        assert!(verify(dir.path()).is_err());
    }

    #[test]
    fn month_names() {
        assert_eq!(civil(0), (1970, 1));
        assert_eq!(civil(1_792_368_000), (2026, 10));
    }
}
