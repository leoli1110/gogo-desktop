use super::*;
use crate::query::{days_from_civil, glob_match};

fn file(size: u64) -> EntryMeta {
    EntryMeta { is_dir: false, size, mtime: 1_700_000_000 }
}
fn dir() -> EntryMeta {
    EntryMeta { is_dir: true, size: 0, mtime: 1_700_000_000 }
}

fn sample() -> NameIndex {
    let mut ix = NameIndex::new();
    ix.set_root(1, 1);
    ix.upsert(1, 10, 1, "Projects", dir(), 1).unwrap();
    ix.upsert(1, 11, 10, "Site A", dir(), 1).unwrap();
    ix.upsert(1, 12, 11, "site_plan.dwg", file(2_000_000), 1).unwrap();
    ix.upsert(1, 13, 11, "fire exit notes.txt", file(1_000), 1).unwrap();
    ix.upsert(1, 14, 10, "plan.pdf", file(50_000), 1).unwrap();
    ix.upsert(1, 15, 1, "draft plan.docx", file(9_000), 1).unwrap();
    ix
}

fn q(s: &str) -> Query {
    parse_query(s, 1_760_000_000).unwrap()
}

#[test]
fn basic_counts_and_paths() {
    let ix = sample();
    assert_eq!(ix.len(), 6);
    assert_eq!(ix.rel_path(1, 12).unwrap(), "Projects/Site A/site_plan.dwg");
    assert_eq!(ix.lookup_path(1, &["Projects", "Site A", "site_plan.dwg"]), Some(12));
    assert_eq!(ix.lookup_path(1, &["Projects", "nope"]), None);
}

#[test]
fn missing_parent_and_unknown_library() {
    let mut ix = sample();
    assert_eq!(ix.upsert(1, 99, 12345, "x", file(1), 1), Err(IndexError::MissingParent));
    assert_eq!(ix.upsert(7, 99, 1, "x", file(1), 1), Err(IndexError::UnknownLibrary));
}

#[test]
fn exact_name_ranks_first() {
    let ix = sample();
    let r = ix.search(&q("plan"), &[1], 10);
    assert_eq!(r.total, 3);
    assert_eq!(r.hits[0].name, "plan.pdf");
}

#[test]
fn rename_and_move_keep_children() {
    let mut ix = sample();
    // Rename folder "Site A" -> "Site B" and move it to the root.
    ix.upsert(1, 11, 1, "Site B", dir(), 2).unwrap();
    assert_eq!(ix.rel_path(1, 12).unwrap(), "Site B/site_plan.dwg");
    assert_eq!(ix.lookup_path(1, &["Projects", "Site A"]), None);
    assert_eq!(ix.lookup_path(1, &["Site B", "site_plan.dwg"]), Some(12));
}

#[test]
fn cannot_move_folder_into_itself() {
    let mut ix = sample();
    assert_eq!(ix.upsert(1, 10, 11, "Projects", dir(), 2), Err(IndexError::MissingParent));
    assert_eq!(ix.rel_path(1, 11).unwrap(), "Projects/Site A");
}

#[test]
fn remove_folder_removes_subtree() {
    let mut ix = sample();
    assert!(ix.remove(1, 10));
    assert_eq!(ix.len(), 1);
    assert!(ix.rel_path(1, 12).is_none());
    assert_eq!(ix.search(&q("plan"), &[1], 10).total, 1);
    // Free slots are reused.
    ix.upsert(1, 20, 1, "new.txt", file(1), 3).unwrap();
    assert_eq!(ix.len(), 2);
}

#[test]
fn same_name_replaces_previous_entry() {
    let mut ix = sample();
    ix.upsert(1, 30, 10, "plan.pdf", file(1), 2).unwrap();
    assert!(ix.rel_path(1, 14).is_none());
    assert_eq!(ix.lookup_path(1, &["Projects", "plan.pdf"]), Some(30));
    assert_eq!(ix.len(), 6);
}

#[test]
fn sweep_removes_unseen_entries() {
    let mut ix = sample();
    for (k, p, n, m) in [(10, 1, "Projects", dir()), (14, 10, "plan.pdf", file(50_000))] {
        ix.upsert(1, k, p, n, m, 2).unwrap();
    }
    let removed = ix.sweep(1, 2);
    assert!(removed >= 2);
    assert_eq!(ix.len(), 2);
}

#[test]
fn filters() {
    let ix = sample();
    assert_eq!(ix.search(&q("ext:dwg"), &[1], 10).total, 1);
    assert_eq!(ix.search(&q("plan -ext:pdf"), &[1], 10).total, 2);
    assert_eq!(ix.search(&q("type:folder"), &[1], 10).total, 2);
    assert_eq!(ix.search(&q("plan type:file size:>40k"), &[1], 10).total, 2);
    // The folder itself and its two files.
    assert_eq!(ix.search(&q("path:\"site a\""), &[1], 10).total, 3);
    assert_eq!(ix.search(&q("path:projects\\site"), &[1], 10).total, 3);
    assert_eq!(ix.search(&q("\"fire exit\""), &[1], 10).total, 1);
    assert_eq!(ix.search(&q("*.dwg"), &[1], 10).total, 1);
    assert_eq!(ix.search(&q("site_????.dwg"), &[1], 10).total, 1);
    assert_eq!(ix.search(&q("plan -draft"), &[1], 10).total, 2);
    assert_eq!(ix.search(&q("modified:2023"), &[1], 10).total, 6);
    assert_eq!(ix.search(&q("modified:>2024"), &[1], 10).total, 0);
}

#[test]
fn library_filter_hides_other_libraries() {
    let mut ix = sample();
    ix.set_root(2, 1);
    ix.upsert(2, 50, 1, "secret plan.txt", file(1), 1).unwrap();
    assert_eq!(ix.search(&q("plan"), &[1], 10).total, 3);
    assert_eq!(ix.search(&q("plan"), &[2], 10).total, 1);
    assert_eq!(ix.search(&q("plan"), &[], 10).total, 0);
}

#[test]
fn unicode_names() {
    let mut ix = NameIndex::new();
    ix.set_root(1, 1);
    ix.upsert(1, 2, 1, "消防出口 平面圖.dwg", file(1), 1).unwrap();
    ix.upsert(1, 3, 1, "ÉCOLE.pdf", file(1), 1).unwrap();
    assert_eq!(ix.search(&q("平面圖"), &[1], 10).total, 1);
    assert_eq!(ix.search(&q("école"), &[1], 10).total, 1);
}

#[test]
fn query_errors() {
    assert_eq!(parse_query("   ", 0), Err(QueryError::Empty));
    assert!(matches!(parse_query("size:>lots", 0), Err(QueryError::BadValue(_))));
    assert!(matches!(parse_query("modified:2026-13", 0), Err(QueryError::BadValue(_))));
    assert!(matches!(parse_query("type:car", 0), Err(QueryError::BadValue(_))));
    assert_eq!(parse_query(&"a".repeat(600), 0), Err(QueryError::TooLong));
    let qq = parse_query("lib:Projects", 0).unwrap();
    assert_eq!(qq.libraries, vec!["Projects".to_string()]);
}

#[test]
fn glob_and_dates() {
    assert!(glob_match("*.dwg", "a.dwg"));
    assert!(glob_match("a*b*c", "axxbyyc"));
    assert!(!glob_match("a?c", "abbc"));
    assert!(glob_match("*", ""));
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(days_from_civil(2026, 10, 19), 20_745);
}

/// Speed check with 1 million entries. Run with:
/// `cargo test --release -p gogo-index -- --ignored --nocapture million`
#[test]
#[ignore]
fn million_entry_speed() {
    let mut ix = NameIndex::new();
    ix.set_root(1, 0);
    let words = ["plan", "site", "report", "invoice", "photo", "drawing", "notes", "budget", "總圖", "dsc"];
    let start = std::time::Instant::now();
    for d in 0..1000u64 {
        let dk = 1_000_000 + d;
        ix.upsert(1, dk, 0, &format!("folder {d}"), dir(), 1).unwrap();
        for f in 0..1000u64 {
            let k = d * 1000 + f + 1;
            let w = words[(k % 10) as usize];
            let w2 = words[((k / 10) % 10) as usize];
            ix.upsert(1, 2_000_000 + k, dk, &format!("{w}_{w2}_{k}.dat"), file(k), 1).unwrap();
        }
    }
    println!("built {} entries in {:?}", ix.len(), start.elapsed());
    for query in ["plan", "invoice_photo", "4242", "*.dat", "總圖 ext:dat", "path:\"folder 99\" notes"] {
        let qq = q(query);
        let t = std::time::Instant::now();
        let r = ix.search(&qq, &[1], 50);
        println!("{query:>24}: {:>8} matches in {:?}", r.total, t.elapsed());
    }
}
