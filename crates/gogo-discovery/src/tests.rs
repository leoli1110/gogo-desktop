use super::*;
use gogo_index::parse_query;
use std::fs;
use std::time::Duration;

fn names(index: &SharedIndex, query: &str) -> Vec<String> {
    let q = parse_query(query, 0).unwrap();
    let mut v: Vec<String> = index.read().search(&q, &[1], 100).hits.into_iter().map(|h| h.rel_path).collect();
    v.sort();
    v
}

fn wait_for<F: Fn() -> bool>(f: F) -> bool {
    for _ in 0..80 {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn spec(root: &std::path::Path) -> LibrarySpec {
    LibrarySpec { id: 1, name: "test".into(), root: root.to_path_buf(), excludes: vec!["*.tmp".into()] }
}

#[test]
fn scan_skips_excluded_and_records_tree() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("Projects/Site A")).unwrap();
    fs::create_dir_all(root.join("@eaDir/thumbs")).unwrap();
    fs::create_dir_all(root.join("#recycle")).unwrap();
    fs::write(root.join("Projects/Site A/plan.dwg"), b"x").unwrap();
    fs::write(root.join("Projects/notes.tmp"), b"x").unwrap();
    fs::write(root.join("@eaDir/thumbs/plan.jpg"), b"x").unwrap();
    let index: SharedIndex = Default::default();
    let stop = AtomicBool::new(false);
    let stats = scan_tree(&index, &spec(root), &DiscoveryOptions::default(), 1, &stop);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.folders, 2);
    assert_eq!(names(&index, "plan"), vec!["Projects/Site A/plan.dwg"]);
    assert!(names(&index, "notes").is_empty());
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"x").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
    let index: SharedIndex = Default::default();
    let stop = AtomicBool::new(false);
    scan_tree(&index, &spec(dir.path()), &DiscoveryOptions::default(), 1, &stop);
    assert!(names(&index, "secret").is_empty());
    assert_eq!(names(&index, "link"), vec!["link"]);
}

#[test]
fn live_changes_are_tracked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(root.join("a/report.txt"), b"1").unwrap();
    let index: SharedIndex = Default::default();
    let opts = DiscoveryOptions { use_ntfs_journal: false, ..Default::default() };
    let h = start_library(spec(&root), index.clone(), opts);
    assert!(wait_for(|| h.status().state == LibraryState::Watching));
    assert_eq!(names(&index, "report"), vec!["a/report.txt"]);

    // Create
    fs::write(root.join("a/invoice.pdf"), b"12345").unwrap();
    assert!(wait_for(|| names(&index, "invoice") == vec!["a/invoice.pdf"]));
    // Rename
    fs::rename(root.join("a/invoice.pdf"), root.join("a/invoice-2026.pdf")).unwrap();
    assert!(wait_for(|| names(&index, "invoice") == vec!["a/invoice-2026.pdf"]));
    // Folder with contents moved in from outside the library
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir_all(outside.path().join("batch/inner")).unwrap();
    fs::write(outside.path().join("batch/inner/photo.arw"), b"x").unwrap();
    if fs::rename(outside.path().join("batch"), root.join("batch")).is_ok() {
        assert!(wait_for(|| names(&index, "photo") == vec!["batch/inner/photo.arw"]));
    }
    // Folder rename keeps children
    fs::rename(root.join("a"), root.join("b")).unwrap();
    assert!(wait_for(|| names(&index, "report") == vec!["b/report.txt"]));
    // Delete
    fs::remove_file(root.join("b/report.txt")).unwrap();
    assert!(wait_for(|| names(&index, "report").is_empty()));
    // Requested re-check keeps the index correct
    h.request_recheck();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(names(&index, "invoice"), vec!["b/invoice-2026.pdf"]);
    h.stop(&index);
    assert!(index.read().is_empty());
}

#[test]
fn missing_root_reports_error() {
    let index: SharedIndex = Default::default();
    let h = start_library(spec(std::path::Path::new("/definitely/not/here")), index, DiscoveryOptions::default());
    assert!(wait_for(|| h.status().state == LibraryState::Error));
}
