//! NTFS discovery: list the whole file table through the change journal and
//! follow changes live. Needs administrator rights (the Windows service runs
//! as LocalSystem). Any failure makes the caller fall back to a folder scan.

use crate::scan::is_excluded;
use crate::{unix_now, Ctx, LibraryState, WatchMethod};
use gogo_index::EntryMeta;
use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW,
    GetVolumePathNameW, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

const FSCTL_ENUM_USN_DATA: u32 = 0x0009_00B3;
const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00BB;
const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00F4;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_JOURNAL_NOT_ACTIVE: u32 = 1179;
const ERROR_JOURNAL_ENTRY_DELETED: u32 = 1181;
const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;

#[repr(C)]
struct MftEnumDataV0 {
    start_file_reference_number: u64,
    low_usn: i64,
    high_usn: i64,
}

#[repr(C)]
#[derive(Default)]
struct UsnJournalDataV0 {
    usn_journal_id: u64,
    first_usn: i64,
    next_usn: i64,
    lowest_valid_usn: i64,
    max_usn: i64,
    maximum_size: u64,
    allocation_delta: u64,
}

#[repr(C)]
struct ReadUsnJournalDataV0 {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: u64,
    bytes_to_wait_for: u64,
    usn_journal_id: u64,
}

/// One parsed USN_RECORD_V2.
#[derive(Clone, Debug)]
pub struct UsnRecord {
    pub frn: u64,
    pub parent: u64,
    pub reason: u32,
    pub attributes: u32,
    pub timestamp: i64,
    pub name: String,
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn filetime_to_unix(ft: i64) -> i64 {
    if ft <= 0 {
        0
    } else {
        ft / 10_000_000 - 11_644_473_600
    }
}

/// Opens the volume that holds `path`, after checking it's NTFS.
fn open_volume(path: &Path) -> Result<Handle, String> {
    let wpath = wide(path.as_os_str());
    let mut vol_root = [0u16; 1024];
    if unsafe { GetVolumePathNameW(wpath.as_ptr(), vol_root.as_mut_ptr(), vol_root.len() as u32) } == 0 {
        return Err(format!("can't find the volume (error {})", last_error()));
    }
    let mut fs_name = [0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(
            vol_root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(format!("can't read volume information (error {})", last_error()));
    }
    let fs = from_wide(&fs_name);
    if !fs.eq_ignore_ascii_case("NTFS") {
        return Err(format!("file system is {fs}, not NTFS"));
    }
    let mut guid = [0u16; 128];
    if unsafe { GetVolumeNameForVolumeMountPointW(vol_root.as_ptr(), guid.as_mut_ptr(), guid.len() as u32) } == 0 {
        return Err(format!("can't resolve the volume name (error {})", last_error()));
    }
    // "\\?\Volume{...}\" -> "\\?\Volume{...}" to open the volume itself.
    let mut device = from_wide(&guid);
    if device.ends_with('\\') {
        device.pop();
    }
    let wdev = wide(std::ffi::OsStr::new(&device));
    let h = unsafe {
        CreateFileW(
            wdev.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(format!(
            "can't open the volume (error {}); the change journal needs administrator rights",
            last_error()
        ));
    }
    Ok(Handle(h))
}

fn query_journal(vol: &Handle) -> Result<UsnJournalDataV0, u32> {
    let mut data = UsnJournalDataV0::default();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            vol.0,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            &mut data as *mut _ as *mut c_void,
            std::mem::size_of::<UsnJournalDataV0>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(last_error())
    } else {
        Ok(data)
    }
}

/// File reference number and basic metadata of a path.
pub fn file_info(path: &Path) -> std::io::Result<(u64, EntryMeta)> {
    let w = wide(path.as_os_str());
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let h = Handle(h);
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(h.0, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let frn = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    let is_dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let ft = ((info.ftLastWriteTime.dwHighDateTime as i64) << 32) | info.ftLastWriteTime.dwLowDateTime as i64;
    let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
    Ok((frn, EntryMeta { is_dir, size: if is_dir { 0 } else { size }, mtime: filetime_to_unix(ft) }))
}

/// Parses the records in a buffer returned by ENUM/READ (after the leading 8 bytes).
pub fn parse_records(buf: &[u8], out: &mut Vec<UsnRecord>) {
    let mut off = 8usize;
    while off + 60 <= buf.len() {
        let rd = |o: usize, n: usize| &buf[off + o..off + o + n];
        let len = u32::from_le_bytes(rd(0, 4).try_into().unwrap()) as usize;
        if len < 60 || off + len > buf.len() {
            break;
        }
        let major = u16::from_le_bytes(rd(4, 2).try_into().unwrap());
        if major == 2 {
            let frn = u64::from_le_bytes(rd(8, 8).try_into().unwrap());
            let parent = u64::from_le_bytes(rd(16, 8).try_into().unwrap());
            let timestamp = i64::from_le_bytes(rd(32, 8).try_into().unwrap());
            let reason = u32::from_le_bytes(rd(40, 4).try_into().unwrap());
            let attributes = u32::from_le_bytes(rd(52, 4).try_into().unwrap());
            let name_len = u16::from_le_bytes(rd(56, 2).try_into().unwrap()) as usize;
            let name_off = u16::from_le_bytes(rd(58, 2).try_into().unwrap()) as usize;
            if name_off + name_len <= len {
                let raw = &buf[off + name_off..off + name_off + name_len];
                let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                out.push(UsnRecord {
                    frn,
                    parent,
                    reason,
                    attributes,
                    timestamp,
                    name: String::from_utf16_lossy(&units),
                });
            }
        }
        off += len;
    }
}

/// Lists every file record on the volume.
fn enumerate(vol: &Handle, high_usn: i64, ctx: &Ctx) -> Result<Vec<UsnRecord>, String> {
    let mut input = MftEnumDataV0 { start_file_reference_number: 0, low_usn: 0, high_usn };
    let mut buf = vec![0u8; 1 << 20];
    let mut out = Vec::new();
    loop {
        if ctx.stopped() {
            return Err("stopped".into());
        }
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                vol.0,
                FSCTL_ENUM_USN_DATA,
                &input as *const _ as *const c_void,
                std::mem::size_of::<MftEnumDataV0>() as u32,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let e = last_error();
            if e == ERROR_HANDLE_EOF {
                break;
            }
            return Err(format!("listing the file table failed (error {e})"));
        }
        if returned <= 8 {
            break;
        }
        input.start_file_reference_number = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        parse_records(&buf[..returned as usize], &mut out);
    }
    Ok(out)
}

/// Builds the library subtree from the enumerated records.
fn load_tree(ctx: &Ctx, root_frn: u64, records: Vec<UsnRecord>, generation: u32) -> (usize, usize) {
    let mut kids: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, r) in records.iter().enumerate() {
        if r.frn != r.parent {
            kids.entry(r.parent).or_default().push(i);
        }
    }
    let spec = &ctx.spec;
    ctx.index.write().set_root(spec.id, root_frn);
    let (mut files, mut folders) = (0, 0);
    let mut stack: Vec<(u64, PathBuf)> = vec![(root_frn, spec.root.clone())];
    let mut ix = ctx.index.write();
    let mut ops = 0usize;
    while let Some((frn, path)) = stack.pop() {
        let Some(children) = kids.get(&frn) else { continue };
        for &i in children {
            let r = &records[i];
            let child_path = path.join(&r.name);
            if is_excluded(&r.name, &child_path, spec, &ctx.opts) {
                continue;
            }
            let is_dir = r.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let meta = EntryMeta { is_dir, size: 0, mtime: 0 };
            if ix.upsert(spec.id, r.frn, frn, &r.name, meta, generation).is_ok() {
                if is_dir {
                    folders += 1;
                    stack.push((r.frn, child_path));
                } else {
                    files += 1;
                }
            }
            ops += 1;
            if ops.is_multiple_of(65_536) {
                // Let searches run during big loads.
                drop(ix);
                std::thread::yield_now();
                ix = ctx.index.write();
            }
        }
    }
    (files, folders)
}

fn full_list(ctx: &Ctx, vol: &Handle, root_frn: u64, generation: u32) -> Result<i64, String> {
    ctx.set(|s| s.state = LibraryState::Scanning);
    let started = Instant::now();
    let journal = query_journal(vol).map_err(|e| {
        if e == ERROR_JOURNAL_NOT_ACTIVE {
            "the volume has no change journal (create one with: fsutil usn createjournal m=1000 a=100 C:)".to_string()
        } else {
            format!("can't query the change journal (error {e})")
        }
    })?;
    let records = enumerate(vol, journal.next_usn, ctx)?;
    let (files, folders) = load_tree(ctx, root_frn, records, generation);
    let removed = ctx.index.write().sweep(ctx.spec.id, generation);
    let ms = started.elapsed().as_millis() as u64;
    tracing::info!(library = %ctx.spec.name, files, folders, removed, ms, "NTFS listing finished");
    ctx.set(|s| {
        s.entries = files + folders;
        s.folders = folders;
        s.last_scan_ms = ms;
        s.last_scan_at = unix_now();
        s.next_recheck_at = unix_now() + ctx.opts.recheck_interval.as_secs() as i64;
        s.method = WatchMethod::NtfsJournal;
        s.state = LibraryState::Watching;
    });
    Ok(journal.next_usn)
}

fn read_journal(vol: &Handle, start_usn: i64, journal_id: u64, buf: &mut [u8]) -> Result<(i64, Vec<UsnRecord>), u32> {
    let input = ReadUsnJournalDataV0 {
        start_usn,
        reason_mask: 0xFFFF_FFFF,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_journal_id: journal_id,
    };
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            vol.0,
            FSCTL_READ_USN_JOURNAL,
            &input as *const _ as *const c_void,
            std::mem::size_of::<ReadUsnJournalDataV0>() as u32,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    if returned < 8 {
        return Ok((start_usn, Vec::new()));
    }
    let next = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let mut out = Vec::new();
    parse_records(&buf[..returned as usize], &mut out);
    Ok((next, out))
}

fn full_path(ctx: &Ctx, frn: u64) -> Option<PathBuf> {
    let rel = ctx.index.read().rel_path(ctx.spec.id, frn)?;
    let mut p = ctx.spec.root.clone();
    for c in rel.split('/') {
        p.push(c);
    }
    Some(p)
}

/// Adds a folder that was moved into the library, with its contents.
fn add_moved_folder(ctx: &Ctx, path: &Path, generation: u32) {
    for entry in walkdir::WalkDir::new(path).follow_links(false).min_depth(1).into_iter().flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_excluded(&name, p, &ctx.spec, &ctx.opts) {
            continue;
        }
        let (Ok((frn, meta)), Some(parent)) = (file_info(p), p.parent()) else { continue };
        let Ok((parent_frn, _)) = file_info(parent) else { continue };
        let _ = ctx.index.write().upsert(ctx.spec.id, frn, parent_frn, &name, meta, generation);
    }
}

fn apply_records(ctx: &Ctx, records: &[UsnRecord], generation: u32) {
    let lib = ctx.spec.id;
    let mut touched: Vec<u64> = Vec::new();
    for r in records {
        if r.reason & USN_REASON_FILE_DELETE != 0 {
            ctx.index.write().remove(lib, r.frn);
            continue;
        }
        if r.reason & USN_REASON_RENAME_OLD_NAME != 0 {
            continue;
        }
        let parent_known = ctx.index.read().meta(lib, r.parent).is_some();
        let known = ctx.index.read().meta(lib, r.frn);
        if !parent_known {
            // Moved out of the library, or a change outside it.
            if known.is_some() {
                ctx.index.write().remove(lib, r.frn);
            }
            continue;
        }
        let parent_path = full_path(ctx, r.parent).unwrap_or_else(|| ctx.spec.root.clone());
        let path = parent_path.join(&r.name);
        if is_excluded(&r.name, &path, &ctx.spec, &ctx.opts) {
            if known.is_some() {
                ctx.index.write().remove(lib, r.frn);
            }
            continue;
        }
        let is_dir = r.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let meta = EntryMeta { is_dir, size: known.map(|m| m.size).unwrap_or(0), mtime: filetime_to_unix(r.timestamp) };
        let _ = ctx.index.write().upsert(lib, r.frn, r.parent, &r.name, meta, generation);
        if is_dir && known.is_none() {
            add_moved_folder(ctx, &path, generation);
        } else if !is_dir {
            touched.push(r.frn);
        }
    }
    touched.sort_unstable();
    touched.dedup();
    for frn in touched {
        if let Some(p) = full_path(ctx, frn) {
            if let Ok(m) = std::fs::symlink_metadata(&p) {
                ctx.index.write().set_meta(lib, frn, crate::scan::meta_of(&m));
            }
        }
    }
}

/// Fills in size and modified time for up to `limit` entries listed without them.
fn fill_meta(ctx: &Ctx, pending: &mut Vec<u64>, limit: usize) {
    let lib = ctx.spec.id;
    for _ in 0..limit {
        let Some(frn) = pending.pop() else { break };
        if let Some(p) = full_path(ctx, frn) {
            if let Ok(m) = std::fs::symlink_metadata(&p) {
                ctx.index.write().set_meta(lib, frn, crate::scan::meta_of(&m));
            }
        }
    }
}

/// Runs NTFS discovery for a library until stopped. Returns an error if the
/// journal can't be used, so the caller can fall back to a folder scan.
pub(crate) fn run(ctx: &Ctx) -> Result<(), String> {
    let root = std::fs::canonicalize(&ctx.spec.root).map_err(|e| e.to_string())?;
    let vol = open_volume(&root)?;
    let (root_frn, _) = file_info(&root).map_err(|e| e.to_string())?;
    let mut generation: u32 = 1;
    let mut usn = full_list(ctx, &vol, root_frn, generation)?;
    let mut journal_id = query_journal(&vol).map_err(|e| format!("journal error {e}"))?.usn_journal_id;
    let mut pending_meta = ctx.index.read().keys_without_meta(ctx.spec.id);
    let mut buf = vec![0u8; 1 << 16];
    let mut next_recheck = Instant::now() + ctx.opts.recheck_interval;
    while !ctx.stopped() {
        match read_journal(&vol, usn, journal_id, &mut buf) {
            Ok((next, records)) => {
                let had = !records.is_empty();
                if had {
                    apply_records(ctx, &records, generation);
                    let n = ctx.index.read().library_len(ctx.spec.id);
                    ctx.set(|s| s.entries = n);
                }
                usn = next;
                if !had {
                    if pending_meta.is_empty() {
                        std::thread::sleep(Duration::from_millis(250));
                    } else {
                        fill_meta(ctx, &mut pending_meta, 2_000);
                    }
                }
            }
            Err(e) if e == ERROR_JOURNAL_ENTRY_DELETED => {
                tracing::warn!(library = %ctx.spec.name, "change journal wrapped; listing again");
                ctx.recheck.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Err(e) => {
                tracing::warn!(library = %ctx.spec.name, "change journal read failed (error {e}); listing again");
                std::thread::sleep(Duration::from_secs(2));
                ctx.recheck.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        if ctx.take_recheck() || Instant::now() >= next_recheck {
            generation = generation.wrapping_add(1).max(1);
            usn = full_list(ctx, &vol, root_frn, generation)?;
            journal_id = query_journal(&vol).map_err(|e| format!("journal error {e}"))?.usn_journal_id;
            pending_meta = ctx.index.read().keys_without_meta(ctx.spec.id);
            next_recheck = Instant::now() + ctx.opts.recheck_interval;
        }
    }
    ctx.set(|s| s.state = LibraryState::Stopped);
    Ok(())
}
