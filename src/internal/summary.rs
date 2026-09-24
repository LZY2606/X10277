//! Deterministic structural summaries of a compound file.
//!
//! The summary is a diagnostic view over exactly the state that the
//! production read path uses (the FAT, DIFAT, MiniFAT, directory chain,
//! and directory entries held by `MiniAllocator`); it adds no logic of its
//! own beyond walking and formatting that state.  Sector IDs and stream
//! IDs are internal numbering: two files with the same logical contents
//! may legitimately differ in them, so the summary relabels them in order
//! of first appearance instead of printing raw values.  As a result, the
//! summary of a file is a pure function of its logical structure, which
//! makes it suitable as a round-trip compatibility gate that is stronger
//! than comparing whole-file binaries (it says *where* the structure
//! diverged) yet insensitive to irrelevant internal renumbering.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::internal::{consts, Allocator, MiniAllocator, ObjType};

//===========================================================================//

/// Walks the FAT chain starting at `start`, defensively stopping at the
/// first invalid or repeated sector ID (files that pass validation never
/// trigger that, but this is a diagnostic tool).
fn walk_fat_chain<F>(allocator: &Allocator<F>, start: u32) -> Vec<u32> {
    let mut ids = Vec::new();
    let mut current = start;
    while current != consts::END_OF_CHAIN && !ids.contains(&current) {
        ids.push(current);
        match allocator.next(current) {
            Ok(next) => current = next,
            Err(_) => break,
        }
    }
    ids
}

/// Walks the MiniFAT chain starting at `start`; see `walk_fat_chain`.
fn walk_mini_chain<F>(minialloc: &MiniAllocator<F>, start: u32) -> Vec<u32> {
    let mut ids = Vec::new();
    let mut current = start;
    while current != consts::END_OF_CHAIN && !ids.contains(&current) {
        ids.push(current);
        match minialloc.next_mini_sector(current) {
            Ok(next) => current = next,
            Err(_) => break,
        }
    }
    ids
}

/// Relabels sector IDs in order of first appearance, so that logically
/// identical files produce identical summaries even when their internal
/// sector numbering differs.
struct SectorLabels {
    labels: HashMap<u32, usize>,
}

impl SectorLabels {
    fn new() -> SectorLabels {
        SectorLabels { labels: HashMap::new() }
    }

    fn label(&mut self, sector_id: u32) -> usize {
        let next = self.labels.len();
        *self.labels.entry(sector_id).or_insert(next)
    }

    fn label_chain(&mut self, chain: &[u32]) -> Vec<usize> {
        chain.iter().map(|&id| self.label(id)).collect()
    }
}

fn format_chain(labels: &[usize]) -> String {
    let mut out = String::from("[");
    for (index, label) in labels.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "S{label}");
    }
    out.push(']');
    out
}

//===========================================================================//

/// Builds the structural summary for the compound file whose state is held
/// by `minialloc`.  `paths` and `stream_ids` must list every directory
/// entry in the order produced by `CompoundFile::walk` (the production
/// preorder traversal), so that entry ordering here cannot drift from what
/// callers observe.
pub fn structural_summary<F>(
    minialloc: &MiniAllocator<F>,
    paths: &[PathBuf],
    stream_ids: &[u32],
) -> String {
    debug_assert_eq!(paths.len(), stream_ids.len());
    let directory = minialloc.directory();
    let allocator = directory.allocator();
    let fat = allocator.fat();
    let minifat = minialloc.minifat();

    // Collect every chain, in a fixed traversal order.
    let dir_chain = directory.dir_sector_ids().to_vec();
    let minifat_chain =
        walk_fat_chain(allocator, minialloc.minifat_start_sector());
    let root_entry = minialloc.root_dir_entry();
    let mini_stream_chain = walk_fat_chain(allocator, root_entry.start_sector);
    let stream_chains: Vec<Vec<u32>> = stream_ids
        .iter()
        .map(|&stream_id| {
            let dir_entry = minialloc.dir_entry(stream_id);
            if dir_entry.obj_type == ObjType::Stream
                && dir_entry.stream_len >= consts::MINI_STREAM_CUTOFF as u64
            {
                walk_fat_chain(allocator, dir_entry.start_sector)
            } else {
                Vec::new()
            }
        })
        .collect();

    // Relabel sectors in that same traversal order: directory chain,
    // MiniFAT chain, mini stream chain, stream chains, FAT sectors, then
    // DIFAT sectors.
    let mut labels = SectorLabels::new();
    let dir_labels = labels.label_chain(&dir_chain);
    let minifat_labels = labels.label_chain(&minifat_chain);
    let mini_stream_labels = labels.label_chain(&mini_stream_chain);
    let stream_labels: Vec<Vec<usize>> = stream_chains
        .iter()
        .map(|chain| labels.label_chain(chain))
        .collect();
    let fat_labels = labels.label_chain(allocator.difat());
    let difat_labels = labels.label_chain(allocator.difat_sector_ids());

    // Any allocated sector that no chain above accounts for is leaked.
    let accounted: HashSet<u32> = labels.labels.keys().copied().collect();
    let unaccounted_sectors = fat
        .iter()
        .enumerate()
        .filter(|&(sector_id, &entry)| {
            entry != consts::FREE_SECTOR
                && entry != consts::FAT_SECTOR
                && entry != consts::DIFAT_SECTOR
                && !accounted.contains(&(sector_id as u32))
        })
        .count();
    let free_sectors =
        fat.iter().filter(|&&entry| entry == consts::FREE_SECTOR).count();

    // Same check on the MiniFAT: walk every mini stream's chain.
    let mut accounted_mini: HashSet<u32> = HashSet::new();
    let mini_chain_lens: Vec<usize> = stream_ids
        .iter()
        .map(|&stream_id| {
            let dir_entry = minialloc.dir_entry(stream_id);
            if dir_entry.obj_type == ObjType::Stream
                && dir_entry.stream_len > 0
                && dir_entry.stream_len < consts::MINI_STREAM_CUTOFF as u64
            {
                let chain = walk_mini_chain(minialloc, dir_entry.start_sector);
                accounted_mini.extend(chain.iter().copied());
                chain.len()
            } else {
                0
            }
        })
        .collect();
    let unaccounted_mini_sectors = minifat
        .iter()
        .enumerate()
        .filter(|&(mini_id, &entry)| {
            entry != consts::FREE_SECTOR
                && !accounted_mini.contains(&(mini_id as u32))
        })
        .count();
    let free_mini_sectors = minifat
        .iter()
        .filter(|&&entry| entry == consts::FREE_SECTOR)
        .count();

    let dir_entries = directory.dir_entries();
    let used_dir_slots = dir_entries
        .iter()
        .filter(|entry| entry.obj_type != ObjType::Unallocated)
        .count();

    let mut out = String::new();
    let _ = writeln!(out, "version: V{}", minialloc.version().number());
    let _ = writeln!(out, "sector-len: {}", minialloc.sector_len());
    let _ = writeln!(out, "dir-chain: {}", format_chain(&dir_labels));
    let _ = writeln!(out, "minifat-chain: {}", format_chain(&minifat_labels));
    let _ = writeln!(
        out,
        "mini-stream-chain: {}",
        format_chain(&mini_stream_labels)
    );
    let _ = writeln!(out, "fat-sectors: {}", format_chain(&fat_labels));
    let _ = writeln!(out, "difat-sectors: {}", format_chain(&difat_labels));
    let _ = writeln!(out, "free-sectors: {free_sectors}");
    let _ = writeln!(out, "unaccounted-sectors: {unaccounted_sectors}");
    let _ = writeln!(out, "minifat-entries: {}", minifat.len());
    let _ = writeln!(out, "free-mini-sectors: {free_mini_sectors}");
    let _ =
        writeln!(out, "unaccounted-mini-sectors: {unaccounted_mini_sectors}");
    let _ = writeln!(
        out,
        "dir-entry-slots: {}/{}",
        used_dir_slots,
        dir_entries.len()
    );
    out.push_str("entries:\n");

    // Map each stream ID to its normalized entry label (walk order).
    let entry_labels: HashMap<u32, usize> = stream_ids
        .iter()
        .enumerate()
        .map(|(index, &stream_id)| (stream_id, index))
        .collect();
    let path_indexes: HashMap<&PathBuf, usize> = paths
        .iter()
        .enumerate()
        .map(|(index, path)| (path, index))
        .collect();
    let label_of = |stream_id: u32| -> String {
        if stream_id == consts::NO_STREAM {
            "-".to_string()
        } else {
            match entry_labels.get(&stream_id) {
                Some(&index) => format!("E{index}"),
                None => "?".to_string(),
            }
        }
    };

    for (index, (path, &stream_id)) in
        paths.iter().zip(stream_ids.iter()).enumerate()
    {
        let dir_entry = minialloc.dir_entry(stream_id);
        let kind = match dir_entry.obj_type {
            ObjType::Root => "root",
            ObjType::Storage => "storage",
            ObjType::Stream => "stream",
            ObjType::Unallocated => "unallocated",
        };
        let parent = match path.parent() {
            Some(parent_path) => {
                match path_indexes.get(&parent_path.to_path_buf()) {
                    Some(&parent_index) => format!("E{parent_index}"),
                    None => "?".to_string(),
                }
            }
            None => "-".to_string(),
        };
        let chain = match dir_entry.obj_type {
            ObjType::Root => {
                format!("reg{}", format_chain(&mini_stream_labels))
            }
            ObjType::Stream => {
                if dir_entry.stream_len == 0 {
                    "empty".to_string()
                } else if dir_entry.stream_len
                    < consts::MINI_STREAM_CUTOFF as u64
                {
                    format!("mini[{}]", mini_chain_lens[index])
                } else {
                    format!("reg{}", format_chain(&stream_labels[index]))
                }
            }
            _ => "-".to_string(),
        };
        let _ = writeln!(
            out,
            "E{index} {} {kind} parent={parent} child={} left={} right={} \
             clsid={} state=0x{:08x} created={} modified={} len={} \
             chain={chain}",
            path.display(),
            label_of(dir_entry.child),
            label_of(dir_entry.left_sibling),
            label_of(dir_entry.right_sibling),
            dir_entry.clsid,
            dir_entry.state_bits,
            dir_entry.creation_time.value(),
            dir_entry.modified_time.value(),
            dir_entry.stream_len,
        );
    }
    out
}

//===========================================================================//
