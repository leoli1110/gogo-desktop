//! Windows-only integration test for the NTFS change journal.
//!
//! Needs administrator rights (to open the volume), so it is ignored by
//! default. CI runs it on `windows-latest` with `cargo test -- --ignored`.

#![cfg(windows)]

use gogo_discovery::{start_library, DiscoveryOptions, LibrarySpec, LibraryState, SharedIndex, WatchMethod};
use std::time::{Duration, Instant};

fn find(index: &SharedIndex, lib: u16, name: &str) -> bool {
    let q = gogo_index::parse_query(name, 0).unwrap();
    index.read().search(&q, &[lib], 10).hits.iter().any(|h| h.name == name)
}

fn wait_for(mut f: impl FnMut() -> bool, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return Some(start.elapsed());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
#[ignore = "needs administrator rights on an NTFS volume"]
fn ntfs_listing_and_live_rename() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("plans")).unwrap();
    for i in 0..500 {
        std::fs::write(dir.path().join("plans").join(format!("drawing-{i}.dwg")), b"x").unwrap();
    }
    std::fs::write(dir.path().join("budget-2026.xlsx"), b"x").unwrap();

    let index = SharedIndex::default();
    let spec = LibrarySpec { id: 1, name: "Test".into(), root: dir.path().to_path_buf(), excludes: vec![] };
    let handle = start_library(spec, index.clone(), DiscoveryOptions::default());

    let ready = wait_for(|| handle.status().state == LibraryState::Watching, Duration::from_secs(60));
    let st = handle.status();
    assert!(ready.is_some(), "library never became ready: {st:?}");
    assert_eq!(st.method, WatchMethod::NtfsJournal, "expected the change journal: {st:?}");
    assert!(st.entries >= 502, "listed {} entries", st.entries);
    assert!(find(&index, 1, "drawing-499.dwg"));
    // The whole volume file table is read to build the library; print the time.
    println!("NTFS listing took {} ms for {} entries", st.last_scan_ms, st.entries);

    // Rename must show up quickly (spec exit test: under 1 second).
    std::fs::rename(dir.path().join("budget-2026.xlsx"), dir.path().join("budget-final.xlsx")).unwrap();
    let seen = wait_for(|| find(&index, 1, "budget-final.xlsx"), Duration::from_secs(5));
    println!("rename visible after {seen:?}");
    assert!(seen.is_some_and(|d| d < Duration::from_secs(1)), "rename took {seen:?}");
    assert!(!find(&index, 1, "budget-2026.xlsx"));

    // Folder moved in from outside the library: its contents appear.
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(outside.path().join("incoming")).unwrap();
    std::fs::write(outside.path().join("incoming").join("survey.dxf"), b"x").unwrap();
    std::fs::rename(outside.path().join("incoming"), dir.path().join("incoming")).unwrap();
    assert!(wait_for(|| find(&index, 1, "survey.dxf"), Duration::from_secs(5)).is_some());

    // Deletes
    std::fs::remove_dir_all(dir.path().join("plans")).unwrap();
    assert!(wait_for(|| !find(&index, 1, "drawing-1.dwg"), Duration::from_secs(5)).is_some());

    handle.stop(&index);
}
