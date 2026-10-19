//! Query language for name search.
//!
//! ```text
//! plan rev            names containing "plan" and "rev"
//! "fire exit"         phrase in the name
//! *.dwg  site_??.dxf  wildcards, matched against the whole name
//! -draft              exclude names containing "draft"
//! ext:pdf,docx        extension filter (also -ext:tmp)
//! path:projects/a     path contains (use / or \)
//! type:folder         folders only (type:file for files)
//! lib:Projects        restrict to a library (by name)
//! size:>10mb          size filters: >, <, = (k, m, g units, 1024-based)
//! modified:2026-03    modified in a year, month or day; also >2026-01-01, <2025, today, 7d
//! ```

use crate::EntryMeta;

/// Size comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeOp {
    Gt,
    Lt,
    Eq,
}

/// One parsed query term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    Name { text: String, neg: bool },
    Glob { pattern: String, neg: bool },
    Ext { exts: Vec<String>, neg: bool },
    Path { text: String, neg: bool },
    Type { dirs: bool },
    Size { op: SizeOp, bytes: u64 },
    Modified { from: i64, to: i64 },
}

/// A parsed query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub terms: Vec<Term>,
    /// Library names from `lib:` filters (the caller maps them to IDs).
    pub libraries: Vec<String>,
}

/// Query parse errors, shown to the user.
#[derive(Debug, PartialEq, Eq)]
pub enum QueryError {
    Empty,
    TooLong,
    BadValue(String),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::Empty => write!(f, "empty query"),
            QueryError::TooLong => write!(f, "query is too long"),
            QueryError::BadValue(v) => write!(f, "can't understand '{v}'"),
        }
    }
}
impl std::error::Error for QueryError {}

const MAX_QUERY_LEN: usize = 512;
const MAX_TERMS: usize = 32;

/// Parses a query string. `now` is the current Unix time (for `today` and `7d`).
pub fn parse_query(input: &str, now: i64) -> Result<Query, QueryError> {
    if input.len() > MAX_QUERY_LEN {
        return Err(QueryError::TooLong);
    }
    let mut q = Query::default();
    for tok in tokenize(input) {
        if q.terms.len() >= MAX_TERMS {
            return Err(QueryError::TooLong);
        }
        let (neg, body) = match tok.strip_prefix('-') {
            Some(rest) if !rest.is_empty() => (true, rest.to_string()),
            _ => (false, tok.clone()),
        };
        if let Some((key, value)) = split_field(&body) {
            let value = unquote(value);
            if value.is_empty() {
                return Err(QueryError::BadValue(tok));
            }
            match key.as_str() {
                "ext" => q.terms.push(Term::Ext {
                    exts: value
                        .split(',')
                        .map(|e| e.trim().trim_start_matches('.').to_lowercase())
                        .filter(|e| !e.is_empty())
                        .collect(),
                    neg,
                }),
                "path" => q.terms.push(Term::Path { text: value.replace('\\', "/").to_lowercase(), neg }),
                "type" | "kind" => match value.to_lowercase().as_str() {
                    "folder" | "dir" | "directory" => q.terms.push(Term::Type { dirs: !neg }),
                    "file" => q.terms.push(Term::Type { dirs: neg }),
                    _ => return Err(QueryError::BadValue(tok)),
                },
                "lib" | "library" => q.libraries.push(value),
                "size" => {
                    let (op, rest) = parse_op(&value);
                    let bytes = parse_size(rest).ok_or_else(|| QueryError::BadValue(tok.clone()))?;
                    q.terms.push(Term::Size { op, bytes });
                }
                "modified" | "date" => {
                    let (op, rest) = parse_op(&value);
                    let (from, to) = parse_period(rest, now).ok_or_else(|| QueryError::BadValue(tok.clone()))?;
                    let (from, to) = match op {
                        SizeOp::Eq => (from, to),
                        SizeOp::Gt => (from, i64::MAX),
                        SizeOp::Lt => (i64::MIN, from),
                    };
                    q.terms.push(Term::Modified { from, to });
                }
                _ => unreachable!("split_field only returns known keys"),
            }
            continue;
        }
        let text = unquote(&body).to_lowercase();
        if text.is_empty() {
            continue;
        }
        if text.contains('*') || text.contains('?') {
            q.terms.push(Term::Glob { pattern: text, neg });
        } else {
            q.terms.push(Term::Name { text, neg });
        }
    }
    if q.terms.is_empty() && q.libraries.is_empty() {
        return Err(QueryError::Empty);
    }
    Ok(q)
}

impl Query {
    /// Checks every non-path term against a lowercase name. Returns a score.
    pub fn match_name(&self, lower: &str, meta: &EntryMeta) -> Option<i64> {
        let mut score = 0i64;
        for t in &self.terms {
            match t {
                Term::Name { text, neg } => {
                    let s = name_score(lower, text);
                    if *neg {
                        if s.is_some() {
                            return None;
                        }
                    } else {
                        score += s?;
                    }
                }
                Term::Glob { pattern, neg } => {
                    let m = glob_match(pattern, lower);
                    if m == *neg {
                        return None;
                    }
                    if m {
                        score += 300;
                    }
                }
                Term::Ext { exts, neg } => {
                    let ext = if meta.is_dir { "" } else { lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("") };
                    let m = exts.iter().any(|e| e == ext);
                    if m == *neg {
                        return None;
                    }
                }
                Term::Type { dirs } => {
                    if meta.is_dir != *dirs {
                        return None;
                    }
                }
                Term::Size { op, bytes } => {
                    if meta.is_dir {
                        return None;
                    }
                    let ok = match op {
                        SizeOp::Gt => meta.size > *bytes,
                        SizeOp::Lt => meta.size < *bytes,
                        SizeOp::Eq => meta.size == *bytes,
                    };
                    if !ok {
                        return None;
                    }
                }
                Term::Modified { from, to } => {
                    if meta.mtime == 0 || meta.mtime < *from || meta.mtime >= *to {
                        return None;
                    }
                }
                Term::Path { .. } => {}
            }
        }
        Some(score)
    }

    /// True if any `path:` term needs the full path.
    pub fn needs_path(&self) -> bool {
        self.terms.iter().any(|t| matches!(t, Term::Path { .. }))
    }

    /// Checks `path:` terms against the lowercase relative path.
    pub fn match_path(&self, lower_path: &str) -> bool {
        self.terms.iter().all(|t| match t {
            Term::Path { text, neg } => lower_path.contains(text.as_str()) != *neg,
            _ => true,
        })
    }
}

fn name_score(lower: &str, term: &str) -> Option<i64> {
    let pos = lower.find(term)?;
    let base = if lower == term {
        1000
    } else if lower.rsplit_once('.').map(|(stem, _)| stem == term).unwrap_or(false) {
        900
    } else if pos == 0 {
        600
    } else if is_word_boundary(lower, pos) || lower.match_indices(term).any(|(p, _)| is_word_boundary(lower, p)) {
        400
    } else {
        200
    };
    let extra = (lower.chars().count() as i64 - term.chars().count() as i64).clamp(0, 200) / 2;
    Some(base - extra)
}

fn is_word_boundary(s: &str, pos: usize) -> bool {
    s[..pos].chars().next_back().map(|c| !c.is_alphanumeric()).unwrap_or(true)
}

/// Whole-string wildcard match (`*` any run, `?` one character).
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern.is_ascii() && text.is_ascii() {
        glob_slice(pattern.as_bytes(), text.as_bytes(), b'?', b'*')
    } else {
        let p: Vec<char> = pattern.chars().collect();
        let t: Vec<char> = text.chars().collect();
        glob_slice(&p, &t, '?', '*')
    }
}

fn glob_slice<T: PartialEq + Copy>(p: &[T], t: &[T], one: T, any: T) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == one || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == any {
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
    while pi < p.len() && p[pi] == any {
        pi += 1;
    }
    pi == p.len()
}

fn tokenize(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in input.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                cur.push(c);
            }
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn split_field(tok: &str) -> Option<(String, &str)> {
    let (k, v) = tok.split_once(':')?;
    let k = k.to_lowercase();
    const KEYS: [&str; 9] = ["ext", "path", "type", "kind", "lib", "library", "size", "modified", "date"];
    KEYS.contains(&k.as_str()).then_some((k, v))
}

fn unquote(s: &str) -> String {
    s.replace('"', "").trim().to_string()
}

fn parse_op(v: &str) -> (SizeOp, &str) {
    if let Some(r) = v.strip_prefix('>') {
        (SizeOp::Gt, r)
    } else if let Some(r) = v.strip_prefix('<') {
        (SizeOp::Lt, r)
    } else if let Some(r) = v.strip_prefix('=') {
        (SizeOp::Eq, r)
    } else {
        (SizeOp::Eq, v)
    }
}

fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim().to_lowercase();
    let split = v.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(v.len());
    let (num, unit) = v.split_at(split);
    let n: f64 = num.parse().ok()?;
    let mult: f64 = match unit {
        "" | "b" => 1.0,
        "k" | "kb" => 1024.0,
        "m" | "mb" => 1024.0 * 1024.0,
        "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" => 1024.0f64.powi(4),
        _ => return None,
    };
    let bytes = n * mult;
    (bytes.is_finite() && bytes >= 0.0 && bytes < u64::MAX as f64).then_some(bytes as u64)
}

/// Parses YYYY, YYYY-MM, YYYY-MM-DD, `today`, or `<n>d` (last n days) into a
/// [from, to) range of Unix seconds (UTC).
fn parse_period(v: &str, now: i64) -> Option<(i64, i64)> {
    let v = v.trim().to_lowercase();
    if v == "today" {
        let start = now - now.rem_euclid(86_400);
        return Some((start, start + 86_400));
    }
    if let Some(n) = v.strip_suffix('d') {
        let days: i64 = n.parse().ok()?;
        if !(1..=36_500).contains(&days) {
            return None;
        }
        return Some((now - days * 86_400, i64::MAX));
    }
    let parts: Vec<&str> = v.split('-').collect();
    let y: i64 = parts.first()?.parse().ok()?;
    if !(1970..=2200).contains(&y) || parts[0].len() != 4 {
        return None;
    }
    match parts.len() {
        1 => Some((days_from_civil(y, 1, 1) * 86_400, days_from_civil(y + 1, 1, 1) * 86_400)),
        2 => {
            let m: u32 = parts[1].parse().ok()?;
            if !(1..=12).contains(&m) {
                return None;
            }
            let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            Some((days_from_civil(y, m, 1) * 86_400, days_from_civil(ny, nm, 1) * 86_400))
        }
        3 => {
            let m: u32 = parts[1].parse().ok()?;
            let d: u32 = parts[2].parse().ok()?;
            if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
                return None;
            }
            let start = days_from_civil(y, m, d) * 86_400;
            Some((start, start + 86_400))
        }
        _ => None,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
