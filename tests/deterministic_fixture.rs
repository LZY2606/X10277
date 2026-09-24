//! Deterministic CFB fixtures and the round-trip compatibility gate.
//!
//! Everything in this file is built exclusively through the crate's public
//! entry points (`cfb::create`/`CompoundFile::create_with_version`,
//! `create_storage`, `create_stream`, `open_stream`, `set_len`,
//! `remove_stream`, `remove_storage`, `flush`, `open_strict`, ...).  No
//! internal object is ever fabricated by the tests: the only "source" of
//! fixture bytes is the repository's own writer, fed a fixed seed.
//!
//! The gate deliberately does *not* compare against a whole-binary golden
//! file.  Instead it verifies:
//!
//!   1. every stream reopens (also under strict validation) with the exact
//!      deterministic contents derived from the fixed seed;
//!   2. a normalized structural summary that records the directory tree,
//!      FAT/minifat allocation usage and allocation-chain lengths, while
//!      hiding legitimate internal numbering (raw sector/stream ids, on-disk
//!      entry slots and physical sector positions);
//!   3. the same logical fixture produced through different operation
//!      orders, stream-buffer sizes, or after a recovered mid-run I/O
//!      failure, yields the same summary.
//!
//! Timestamps are pinned from the seed (they are the only non-determinism
//! source in the writer), so byte-identical reruns are additionally checked
//! where semantically required.

use std::collections::BTreeMap;
use std::io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom, Write};
use std::time::{Duration, UNIX_EPOCH};

use cfb::{CompoundFile, OpenOptions, Version};

//===========================================================================//
// Deterministic, dependency-free random source (fixed seed only):

/// SplitMix64: tiny, fully deterministic PRNG.  The fixtures depend only on
/// repository code plus this fixed-seed generator -- no `rand`, no external
/// files, no machine-local data.
#[derive(Clone, Debug)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> SplitMix64 {
        SplitMix64(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    /// Deterministic payload for the stream at `path`: `len` bytes that are
    /// reproducible from the path name alone, independent of the order in
    /// which streams happen to be created.
    fn payload(path: &str, len: usize) -> Vec<u8> {
        let seed = path.bytes().fold(0x9E37_79B9_7F4A_7C15u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        });
        let mut rng = SplitMix64::new(seed ^ 0xD1B5_4A32_589F_24E5);
        (0..len).map(|_| rng.byte()).collect()
    }
}

/// Pinned timestamp: 2024-01-02T03:04:05Z.  All entries get an explicit
/// creation/modification time derived from this constant, so the generated
/// bytes contain no wall-clock dependence.
const FIXED_EPOCH_SECS: u64 = 1_704_155_045;

fn fixed_time(salt: u64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(FIXED_EPOCH_SECS + salt)
}

/// Salt for an entry's pinned timestamp: stable across creation orders
/// because it derives from the path, not from an insertion counter.
fn time_salt(path: &str) -> u64 {
    path.bytes().fold(0x1234_5678u64, |acc, b| {
        acc.rotate_left(5) ^ (b as u64)
    }) % 60
}

//===========================================================================//
// The fixed fixture manifest.
//
// A single fixed-seed scenario that exercises every allocation regime:
// empty, mini, mini-sector boundary, mini/fat cutoff, exact regular sector
// multiples, and multi-sector long streams; nested and UTF-16 storages;
// tree-rotation pressure; grow/shrink; and delete-then-reuse.  Every
// non-removed stream below has pinned contents via `SplitMix64::payload`.

#[derive(Clone, Copy, Debug)]
struct StreamSpec {
    path: &'static str,
    len: usize,
}

/// Groups are independent and can be (re)ordered without changing the final
/// logical file; within a group the order is fixed.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// Recursively create a storage subtree.
    Storage(&'static str),
    /// Create a stream and write its pinned payload.
    Write(StreamSpec),
    /// Create, write, grow/shrink, rewrite to the final pinned payload.
    GrowShrink(StreamSpec),
    /// Write a payload, remove it, recreate at the same path, write `reused`.
    DeleteReuse { victim: StreamSpec, reused: StreamSpec },
}

fn fixture_groups(version: Version) -> Vec<Vec<Step>> {
    let sector_len = version.sector_len() as usize;
    vec![
        // --- Nested storages, including a UTF-16 path ------------------
        vec![
            Step::Storage("/doc"),
            Step::Storage("/doc/日本語"),
            Step::Storage("/doc/子"),
            Step::Storage("/rot"),
            Step::Storage("/tmp"),
        ],
        // --- Mini streams: empty, single byte, mini-sector boundary ----
        vec![
            Step::Write(StreamSpec { path: "/empty", len: 0 }),
            Step::Write(StreamSpec { path: "/doc/a", len: 1 }),
            Step::Write(StreamSpec { path: "/doc/b", len: 63 }),
            Step::Write(StreamSpec { path: "/doc/c", len: 64 }),
            Step::Write(StreamSpec { path: "/doc/d", len: 65 }),
            Step::Write(StreamSpec { path: "/doc/日本語/ストリーム", len: 200 }),
        ],
        // --- Mini/fat cutoff on both sides -----------------------------
        vec![
            Step::Write(StreamSpec { path: "/just-mini", len: 4095 }),
            Step::Write(StreamSpec { path: "/just-fat", len: 4096 }),
        ],
        // --- Regular-sector boundary on both sides ---------------------
        vec![
            Step::Write(StreamSpec {
                path: "/sector-minus",
                len: sector_len - 1,
            }),
            Step::Write(StreamSpec {
                path: "/sector-exact",
                len: sector_len,
            }),
            Step::Write(StreamSpec {
                path: "/sector-plus",
                len: sector_len + 1,
            }),
            Step::Write(StreamSpec { path: "/long", len: sector_len * 7 + 123 }),
        ],
        // --- Case preservation (case-insensitive identity lives in /doc)
        vec![
            Step::Storage("/Case"),
            Step::Write(StreamSpec { path: "/Case/MixedName", len: 300 }),
        ],
        // --- Red-black tree rotation pressure inside one storage -------
        vec![{
            // 24 siblings, inserted shortlex order; the balancing code must
            // rotate repeatedly while keeping shortlex iteration order.
            Step::Storage("/rot/keep")
        }],
        // --- Grow/shrink across the mini/fat boundary ------------------
        vec![
            Step::GrowShrink(StreamSpec {
                path: "/resized",
                len: sector_len * 2 + 500,
            }),
        ],
        // --- Delete + sector/dir-slot reuse ----------------------------
        vec![
            Step::DeleteReuse {
                victim: StreamSpec { path: "/tmp/victim", len: 20_000 },
                reused: StreamSpec { path: "/recycled", len: 20_000 },
            },
        ],
    ]
}

/// Sibling entries under `/rot/keep` used to force directory tree rotations.
fn rotation_names() -> [&'static str; 24] {
    [
        "a0", "a1", "b0", "b1", "c0", "c1", "d0", "d1", "e0", "e1", "f0",
        "f1", "g0", "g1", "h0", "h1", "i0", "i1", "j0", "j1", "k0", "k1",
        "l0", "l1",
    ]
}

/// All streams expected to exist after the fixture is complete, with their
/// final pinned lengths.  `None` marks paths that must not exist.
fn expected_streams(version: Version) -> Vec<(String, Option<usize>)> {
    let sector_len = version.sector_len() as usize;
    let mut streams: Vec<(String, Option<usize>)> = vec![
        ("/empty".into(), Some(0)),
        ("/doc/a".into(), Some(1)),
        ("/doc/b".into(), Some(63)),
        ("/doc/c".into(), Some(64)),
        ("/doc/d".into(), Some(65)),
        ("/doc/日本語/ストリーム".into(), Some(200)),
        ("/just-mini".into(), Some(4095)),
        ("/just-fat".into(), Some(4096)),
        ("/sector-minus".into(), Some(sector_len - 1)),
        ("/sector-exact".into(), Some(sector_len)),
        ("/sector-plus".into(), Some(sector_len + 1)),
        ("/long".into(), Some(sector_len * 7 + 123)),
        ("/Case/MixedName".into(), Some(300)),
        ("/resized".into(), Some(sector_len * 2 + 500)),
        ("/tmp/victim".into(), None),
        ("/recycled".into(), Some(20_000)),
    ];
    for name in rotation_names() {
        streams.push((format!("/rot/keep/{name}"), Some(32)));
    }
    streams
}

/// Storages expected to exist after the fixture is complete.
fn expected_storages() -> Vec<&'static str> {
    // /doc/子 is an empty leaf storage, kept on purpose.
    vec!["/doc", "/doc/日本語", "/doc/子", "/rot", "/rot/keep", "/tmp", "/Case"]
}

//===========================================================================//
// Fixture builder -- public entry points only.

/// Order in which the (independent) fixture groups are executed.  The final
/// logical file is identical for every order.
#[derive(Clone, Copy, Debug)]
enum BuildOrder {
    Canonical,
    /// Reverse the independent groups.
    Reversed,
}

fn ordered_groups(
    version: Version,
    order: BuildOrder,
) -> Vec<Vec<Step>> {
    let mut groups = fixture_groups(version);
    if matches!(order, BuildOrder::Reversed) {
        groups.reverse();
    }
    groups
}

fn write_payload<F: Read + Write + Seek>(
    comp: &mut CompoundFile<F>,
    path: &str,
    len: usize,
) -> io::Result<()> {
    // Groups must be reorderable, so each write ensures its parent exists.
    comp.create_storage_all(parent_of(path))?;
    let data = SplitMix64::payload(path, len);
    let mut stream = comp.create_stream(path)?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
}

fn apply_step<F: Read + Write + Seek>(
    comp: &mut CompoundFile<F>,
    step: Step,
) -> io::Result<()> {
    match step {
        Step::Storage(path) => comp.create_storage_all(path),
        Step::Write(spec) => write_payload(comp, spec.path, spec.len),
        Step::GrowShrink(spec) => {
            // Grow well into the FAT, shrink back below the mini cutoff,
            // then grow to the final size.  Prefix data must survive every
            // resize; newly grown regions must read back as zeroes.
            let path = spec.path;
            let final_len = spec.len;
            let mut stream = comp.create_stream(path)?;
            stream.set_len(7000)?;
            stream.seek(SeekFrom::Start(0))?;
            stream.write_all(&SplitMix64::payload(path, 200))?;
            stream.set_len(300)?;
            stream.set_len(8000)?;
            stream.set_len(final_len as u64)?;
            // Rewrite the complete pinned payload for a deterministic end.
            let data = SplitMix64::payload(path, final_len);
            stream.seek(SeekFrom::Start(0))?;
            stream.write_all(&data)?;
            stream.flush()
        }
        Step::DeleteReuse { victim, reused } => {
            write_payload(comp, victim.path, victim.len)?;
            comp.remove_stream(victim.path)?;
            // Reuse the freed space (and directory entry slot) for a fresh
            // stream under a different name.
            write_payload(comp, reused.path, reused.len)
        }
    }
}

/// Adds the rotation-pressure siblings of `/rot/keep`.  These are applied
/// after the groups, regardless of group ordering.
fn add_rotation_entries<F: Read + Write + Seek>(
    comp: &mut CompoundFile<F>,
) -> io::Result<()> {
    for name in rotation_names() {
        let path = format!("/rot/keep/{name}");
        let data = SplitMix64::payload(&path, 32);
        let mut stream = comp.create_stream(&path)?;
        stream.write_all(&data)?;
        stream.flush()?;
    }
    Ok(())
}

/// Pins every entry's timestamps from its path, eliminating the writer's
/// only wall-clock input.
fn pin_timestamps<F: Read + Write + Seek>(
    comp: &mut CompoundFile<F>,
) -> io::Result<()> {
    let paths: Vec<String> =
        comp.walk().map(|entry| entry.path().display().to_string()).collect();
    for path in paths {
        let salt = time_salt(&path);
        comp.set_created_time(&path, fixed_time(salt))?;
        comp.set_modified_time(&path, fixed_time(salt + 7))?;
    }
    Ok(())
}

struct BuildOpts {
    order: BuildOrder,
    max_buffer_size: usize,
    double_save: bool,
}

impl Default for BuildOpts {
    fn default() -> Self {
        BuildOpts {
            order: BuildOrder::Canonical,
            max_buffer_size: 4096,
            double_save: true,
        }
    }
}

/// Runs the complete fixture scenario through public calls, returning the
/// final on-disk bytes.  The first save happens after groups/rotations; the
/// second ("save again") after timestamp pinning.
fn build_fixture(
    version: Version,
    opts: &BuildOpts,
    writer: impl Read + Write + Seek,
) -> io::Result<()> {
    // Version selection goes through the existing public entries; V4 is
    // what `OpenOptions::create_with` produces, while V3 uses the explicit
    // `create_with_version` entry (buffer-size variants are therefore
    // exercised on the V4 path).
    let mut comp: CompoundFile<_> = if version == Version::V4 {
        OpenOptions::new()
            .max_buffer_size(opts.max_buffer_size)
            .create_with(writer)?
    } else {
        assert_eq!(
            opts.max_buffer_size,
            4096,
            "buffer-size variants are run through the V4 public path"
        );
        CompoundFile::create_with_version(version, writer)?
    };
    for group in ordered_groups(version, opts.order) {
        for step in group {
            apply_step(&mut comp, step)?;
        }
    }
    add_rotation_entries(&mut comp)?;
    comp.flush()?;
    if opts.double_save {
        // A second save with no logical changes must be a no-op for content
        // and structure.
        pin_timestamps(&mut comp)?;
        comp.flush()?;
    }
    drop(comp);
    Ok(())
}

fn build_fixture_bytes(
    version: Version,
    opts: &BuildOpts,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    build_fixture(version, opts, Cursor::new(&mut bytes))?;
    Ok(bytes)
}

/// Opens `bytes` with strict validation (the cross-implementation
/// compatibility gate: any spec violation is rejected).
fn open_gate(bytes: &[u8]) -> io::Result<CompoundFile<Cursor<&[u8]>>> {
    CompoundFile::open_strict(Cursor::new(bytes))
}

//===========================================================================//
// Normalized structural summary.
//
// The summary captures the allocation chains (mini vs FAT, chain lengths in
// sectors) and the directory relationships (parent -> sorted children), but
// deliberately hides every legitimate internal numbering difference: raw
// stream ids, on-disk directory slots, and physical sector positions.  Two
// builds of the same logical fixture therefore produce the same summary even
// when their physical layouts differ.

const MINI_STREAM_CUTOFF: u64 = 4096;
const MINI_SECTOR_LEN: u64 = 64;

fn chain_class(len: u64) -> &'static str {
    if len < MINI_STREAM_CUTOFF {
        "mini"
    } else {
        "fat"
    }
}

fn chain_sectors(len: u64, sector_len: u64) -> u64 {
    if len == 0 {
        0
    } else if len < MINI_STREAM_CUTOFF {
        len.div_ceil(MINI_SECTOR_LEN)
    } else {
        len.div_ceil(sector_len)
    }
}

fn structural_summary(bytes: &[u8]) -> String {
    let comp = open_gate(bytes).expect("gate: strict reopen");
    let version = comp.version();
    let sector_len = version.sector_len() as u64;

    let mut out = String::new();
    out.push_str(&format!(
        "version={:?} sector_len={} file_sectors={}\n",
        version,
        sector_len,
        bytes.len() / sector_len as usize
    ));

    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut mini_stream_count = 0u64;
    let mut fat_stream_count = 0u64;
    let mut mini_sectors_used = 0u64;
    let mut fat_sectors_used = 0u64;

    for entry in comp.walk() {
        let path = entry.path().display().to_string();
        let kind = if entry.is_root() {
            "root"
        } else if entry.is_storage() {
            "storage"
        } else {
            "stream"
        };
        let mut line = format!("{kind} {path}");
        if entry.is_stream() {
            let len = entry.len();
            let class = chain_class(len);
            let sectors = chain_sectors(len, sector_len);
            line.push_str(&format!(" len={len} chain={class}:{sectors}"));
            if class == "mini" {
                mini_stream_count += 1;
                mini_sectors_used += sectors;
            } else {
                fat_stream_count += 1;
                fat_sectors_used += sectors;
            }
        }
        entries.push((path.clone(), line));
        if !entry.is_root() {
            let parent = parent_of(&path);
            children
                .entry(parent)
                .or_default()
                .push(entry.name().to_string());
        }
    }
    entries.sort();
    for (_, line) in entries {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("children:\n");
    for (parent, mut kids) in children {
        kids.sort();
        out.push_str(&format!("  {parent} -> [{}]\n", kids.join(", ")));
    }
    out.push_str(&format!(
        "totals: mini_streams={} fat_streams={} mini_sectors={} fat_sectors={}\n",
        mini_stream_count, fat_stream_count, mini_sectors_used, fat_sectors_used
    ));
    out
}

fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => path[..index].to_string(),
    }
}

//===========================================================================//
// Compatibility gate: reopen, verify contents and structural invariants.
// Every failure reports the first violating location with context.

fn gate_check(version: Version, bytes: &[u8]) -> Result<(), String> {
    let mut comp = open_gate(bytes)
        .map_err(|e| format!("strict reopen failed: {e}"))?;
    if comp.version() != version {
        return Err(format!(
            "version mismatch: expected {:?}, found {:?}",
            version,
            comp.version()
        ));
    }

    // Directory relationships and stream contents.
    for (path, expected_len) in expected_streams(version) {
        match expected_len {
            Some(len) => {
                if !comp.is_stream(&path) {
                    return Err(format!("missing stream: {path}"));
                }
                let entry = comp
                    .entry(&path)
                    .map_err(|e| format!("entry({path}): {e}"))?;
                if entry.len() != len as u64 {
                    return Err(format!(
                        "length mismatch at {path}: expected {len}, found {}",
                        entry.len()
                    ));
                }
                let mut data = Vec::new();
                comp.open_stream(&path)
                    .map_err(|e| format!("open_stream({path}): {e}"))?
                    .read_to_end(&mut data)
                    .map_err(|e| format!("read({path}): {e}"))?;
                let expected = SplitMix64::payload(&path, len);
                if data != expected {
                    let at = data
                        .iter()
                        .zip(expected.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or_else(|| data.len().min(expected.len()));
                    return Err(format!(
                        "content mismatch at {path}: first differing byte \
                         at offset {at} (found {found:#04x}, expected \
                         {want:#04x})",
                        found = data.get(at).copied().unwrap_or(0),
                        want = expected.get(at).copied().unwrap_or(0),
                    ));
                }
            }
            None => {
                if comp.exists(&path) {
                    return Err(format!(
                        "path should have been removed but still exists: {path}"
                    ));
                }
            }
        }
    }
    for storage in expected_storages() {
        if !comp.is_storage(storage) {
            return Err(format!("missing storage: {storage}"));
        }
    }

    // Case-insensitive identity with case-preserved names.
    let mixed = comp
        .entry("/Case/MixedName")
        .map_err(|e| format!("entry(/Case/MixedName): {e}"))?;
    if mixed.name() != "MixedName" {
        return Err(format!(
            "case not preserved: expected 'MixedName', found '{}'",
            mixed.name()
        ));
    }
    if !comp.exists("/case/mixedname") {
        return Err(
            "case-insensitive lookup failed for /case/mixedname".to_string()
        );
    }

    // UTF-16 names round-trip exactly.
    let utf16 = comp
        .entry("/doc/日本語/ストリーム")
        .map_err(|e| format!("entry(utf16 stream): {e}"))?;
    if utf16.name() != "ストリーム" {
        return Err(format!(
            "UTF-16 name mismatch: expected 'ストリーム', found '{}'",
            utf16.name()
        ));
    }

    // Rotation-pressure storage: children iterate in CFB shortlex order.
    let names: Vec<String> = comp
        .read_storage("/rot/keep")
        .map_err(|e| format!("read_storage(/rot/keep): {e}"))?
        .map(|entry| entry.name().to_string())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    if names != sorted {
        return Err(format!(
            "directory iteration not in shortlex order under /rot/keep: \
             {names:?}"
        ));
    }
    Ok(())
}

fn gate(version: Version, bytes: &[u8]) {
    if let Err(message) = gate_check(version, bytes) {
        panic!("compatibility gate violation: {message}");
    }
}

//===========================================================================//
// Recoverable failure injection at the public reader/writer boundary.
//
// `create_with` accepts any `Read + Write + Seek`, so a misbehaving backing
// store is a legitimate way to inject an I/O failure without touching
// internals.  Injected failures surface as ordinary `io::Error`s (the
// existing error layering).

struct FlakyIo {
    inner: Cursor<Vec<u8>>,
    /// Fail the Nth `flush` call (once), then recover automatically.
    fail_flush_once: Option<u64>,
    flush_count: u64,
    /// Fail any write that would extend the backing file beyond this size.
    fail_writes_above: Option<u64>,
}

impl FlakyIo {
    fn failing_flush(fail_on_call: u64) -> FlakyIo {
        FlakyIo {
            inner: Cursor::new(Vec::new()),
            fail_flush_once: Some(fail_on_call),
            flush_count: 0,
            fail_writes_above: None,
        }
    }

    fn failing_write(limit: u64) -> FlakyIo {
        FlakyIo {
            inner: Cursor::new(Vec::new()),
            fail_flush_once: None,
            flush_count: 0,
            fail_writes_above: Some(limit),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.inner.into_inner()
    }
}

impl Read for FlakyIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for FlakyIo {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl Write for FlakyIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(limit) = self.fail_writes_above {
            if self.inner.position() + buf.len() as u64 > limit {
                return Err(io::Error::new(
                    ErrorKind::StorageFull,
                    "injected deterministic write failure",
                ));
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_count += 1;
        if self.fail_flush_once == Some(self.flush_count) {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "injected deterministic flush failure",
            ));
        }
        self.inner.flush()
    }
}

//===========================================================================//
// Tests: baseline + the six boundary/rotation/mutation counterexamples.

#[test]
fn fixture_small_roundtrip_baseline() {
    // Smallest reproducible input first: an empty CFB with one mini stream,
    // round-tripped through the public entries and strict gate.
    let mut bytes = Vec::new();
    {
        let mut comp = CompoundFile::create(Cursor::new(&mut bytes)).unwrap();
        comp.create_storage("/s").unwrap();
        comp.create_stream("/s/x").unwrap().write_all(b"hello").unwrap();
        comp.flush().unwrap();
    }
    {
        let mut comp = open_gate(&bytes).expect("gate");
        let mut data = Vec::new();
        comp.open_stream("/s/x").unwrap().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"hello");
        assert!(comp.is_storage("/s"));
    }
}

#[test]
fn fixture_canonical_v3_passes_gate() {
    let bytes =
        build_fixture_bytes(Version::V3, &BuildOpts::default()).unwrap();
    gate(Version::V3, &bytes);
}

#[test]
fn fixture_canonical_v4_passes_gate() {
    let bytes =
        build_fixture_bytes(Version::V4, &BuildOpts::default()).unwrap();
    gate(Version::V4, &bytes);
}

#[test]
fn fixture_sector_boundaries_roundtrip_v3() {
    // Both sides of every boundary that changes allocation: mini sector
    // (64), mini/fat cutoff (4096), and regular sector (512 for V3).
    let lengths = [
        0usize, 1, 63, 64, 65, 511, 512, 513, 4095, 4096, 4097, 1024,
    ];
    let mut bytes = Vec::new();
    {
        let mut comp =
            CompoundFile::create_with_version(Version::V3, Cursor::new(&mut bytes))
                .unwrap();
        for (index, &len) in lengths.iter().enumerate() {
            let path = format!("/b{index}");
            let data = SplitMix64::payload(&path, len);
            let mut stream = comp.create_stream(&path).unwrap();
            stream.write_all(&data).unwrap();
            stream.flush().unwrap();
        }
        comp.flush().unwrap();
    }
    let mut comp = open_gate(&bytes).expect("gate");
    for (index, &len) in lengths.iter().enumerate() {
        let path = format!("/b{index}");
        let entry = comp.entry(&path).unwrap();
        let expected_class = if len < 4096 { "mini" } else { "fat" };
        let expected_sectors = if len == 0 {
            0
        } else if len < 4096 {
            len.div_ceil(64)
        } else {
            len.div_ceil(512)
        };
        assert_eq!(entry.len(), len as u64, "length at {path}");
        assert_eq!(
            chain_class(entry.len()),
            expected_class,
            "chain class at {path}"
        );
        assert_eq!(
            chain_sectors(entry.len(), 512),
            expected_sectors as u64,
            "chain sectors at {path}"
        );
        let mut data = Vec::new();
        comp.open_stream(&path).unwrap().read_to_end(&mut data).unwrap();
        assert_eq!(data, SplitMix64::payload(&path, len), "data at {path}");
    }
}

#[test]
fn fixture_name_case_and_utf16_rules() {
    let mut bytes = Vec::new();
    {
        let mut comp = CompoundFile::create(Cursor::new(&mut bytes)).unwrap();
        comp.create_storage_all("/doc/日本語").unwrap();
        let mut stream =
            comp.create_stream("/doc/日本語/ストリーム café").unwrap();
        stream.write_all(b"utf16").unwrap();
        stream.flush().unwrap();
        comp.create_stream("/CaseTest").unwrap();
        // Different case spells the same CFB name: create_new must reject it
        // through the existing AlreadyExists error layer.
        let error = comp.create_new_stream("/CASETEST").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        // Overwriting through create_stream truncates the existing entry
        // rather than creating a second one.
        comp.create_stream("/casetest").unwrap();
        // Name-length rule is in UTF-16 code units.
        let max_name = "a".repeat(31);
        comp.create_new_stream(&format!("/{max_name}")).unwrap();
        let too_long = "a".repeat(32);
        let error = comp.create_new_stream(&format!("/{too_long}")).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        // A supplementary-plane char costs two UTF-16 code units.
        let emoji_ok = format!("/{}", "😀".repeat(15)); // 30 units
        comp.create_new_stream(&emoji_ok).unwrap();
        let emoji_bad = format!("/{}", "😀".repeat(16)); // 32 units
        let error = comp.create_new_stream(&emoji_bad).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        // Forbidden characters keep their error class.
        let error = comp.create_stream("/bad:name").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        // A missing parent storage is reported through NotFound.
        let error = comp.create_stream("/missing/kid").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        comp.flush().unwrap();
    }
    let mut comp = open_gate(&bytes).expect("gate");
    assert!(comp.exists("/DOC/日本語/ストリーム café"));
    let entry = comp.entry("/doc/日本語/ストリーム café").unwrap();
    assert_eq!(entry.name(), "ストリーム café");
    // The case-variant overwrote the original: exactly one such entry.
    assert!(comp.is_stream("/casetest"));
    let count = comp
        .walk()
        .filter(|entry| {
            entry.is_stream()
                && entry.name().to_ascii_uppercase() == "CASETEST"
        })
        .count();
    assert_eq!(count, 1, "duplicate case-variant entries");
}

#[test]
fn fixture_directory_tree_rotation_preserves_order() {
    let mut bytes = Vec::new();
    {
        let mut comp = CompoundFile::create(Cursor::new(&mut bytes)).unwrap();
        // Sequential shortlex insertions force repeated red-black rotations,
        // then remove half of the leaves (forcing deletion rotations).
        let names: Vec<String> =
            (0..40).map(|index| format!("n{index:02}")).collect();
        for name in &names {
            comp.create_new_stream(&format!("/{name}")).unwrap();
        }
        for name in names.iter().step_by(2) {
            comp.remove_stream(&format!("/{name}")).unwrap();
        }
        comp.flush().unwrap();
    }
    let mut comp = open_gate(&bytes).expect("gate");
    let listed: Vec<String> = comp
        .read_root_storage()
        .map(|entry| entry.name().to_string())
        .collect();
    let expected: Vec<String> =
        (0..40).filter(|i| i % 2 == 1).map(|i| format!("n{i:02}")).collect();
    assert_eq!(
        listed, expected,
        "survivors must iterate in shortlex order after rotation-heavy edits"
    );
    // Removed entries stay gone; survivors keep deterministic content slots.
    assert!(!comp.exists("/n00"));
    assert!(comp.is_stream("/n01"));
}

#[test]
fn fixture_stream_grow_shrink_preserves_prefix() {
    let mut bytes = Vec::new();
    {
        let mut comp = CompoundFile::create(Cursor::new(&mut bytes)).unwrap();
        let mut stream = comp.create_stream("/g").unwrap();
        stream.set_len(10_000).unwrap(); // FAT-backed
        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.write_all(&SplitMix64::payload("/g", 1000)).unwrap();
        stream.set_len(300).unwrap(); // shrink into the mini stream
        stream.set_len(9_000).unwrap(); // grow back to FAT
        stream.flush().unwrap();
        drop(stream);
        comp.flush().unwrap();
    }
    let mut comp = open_gate(&bytes).expect("gate");
    let entry = comp.entry("/g").unwrap();
    assert_eq!(entry.len(), 9_000);
    assert_eq!(chain_class(entry.len()), "fat");
    let mut data = Vec::new();
    comp.open_stream("/g").unwrap().read_to_end(&mut data).unwrap();
    assert_eq!(&data[..300], &SplitMix64::payload("/g", 1000)[..300]);
    assert!(data[300..].iter().all(|&byte| byte == 0), "grown tail zeroed");
}

#[test]
fn fixture_delete_reuse_does_not_grow_file() {
    let victim = SplitMix64::payload("/victim", 20_000);
    let reused = SplitMix64::payload("/reused", 20_000);
    let mut bytes = Vec::new();
    let size_after_remove;
    {
        let mut comp = CompoundFile::create(Cursor::new(&mut bytes)).unwrap();
        let mut stream = comp.create_stream("/victim").unwrap();
        stream.write_all(&victim).unwrap();
        stream.flush().unwrap();
        drop(stream);
        comp.flush().unwrap();
        let size_with_victim = bytes.len();
        comp.remove_stream("/victim").unwrap();
        comp.flush().unwrap();
        size_after_remove = bytes.len();
        assert_eq!(size_with_victim, size_after_remove, "file never shrinks in place");
        let mut stream = comp.create_stream("/reused").unwrap();
        stream.write_all(&reused).unwrap();
        stream.flush().unwrap();
        drop(stream);
        comp.flush().unwrap();
        // Equal-sized replacement must reuse freed chains: no growth.
        assert_eq!(bytes.len(), size_after_remove, "freed chains must be reused");
    }
    let mut comp = open_gate(&bytes).expect("gate");
    assert!(!comp.exists("/victim"));
    let mut data = Vec::new();
    comp.open_stream("/reused").unwrap().read_to_end(&mut data).unwrap();
    assert_eq!(data, reused);
}

#[test]
fn fixture_two_consecutive_saves_are_stable() {
    let first =
        build_fixture_bytes(Version::V3, &BuildOpts::default()).unwrap();
    gate(Version::V3, &first);
    // Reopen and save the unchanged file a second time.
    // `open` on a Read+Write+Seek backing store yields a writable file.
    let mut comp = CompoundFile::open(Cursor::new(first.clone())).unwrap();
    comp.flush().unwrap();
    let second = comp.into_inner().into_inner();
    gate(Version::V3, &second);
    assert_eq!(
        structural_summary(&first),
        structural_summary(&second),
        "summary must not drift after a second save"
    );
}

//===========================================================================//
// Tests: determinism under reordered operations and cache/buffer variants.

#[test]
fn fixture_summary_stable_under_reordered_groups() {
    let canonical =
        build_fixture_bytes(Version::V3, &BuildOpts::default()).unwrap();
    let reversed = build_fixture_bytes(
        Version::V3,
        &BuildOpts { order: BuildOrder::Reversed, ..BuildOpts::default() },
    )
    .unwrap();
    gate(Version::V3, &reversed);
    assert_eq!(
        structural_summary(&canonical),
        structural_summary(&reversed),
        "reordering independent groups must not change the summary"
    );
}

#[test]
fn fixture_bytes_stable_under_stream_buffer_sizes() {
    // Buffer size is a pure performance knob: tiny vs huge buffers must
    // produce byte-identical files on the V4 public path.
    let default_buf =
        build_fixture_bytes(Version::V4, &BuildOpts::default()).unwrap();
    let tiny_buf = build_fixture_bytes(
        Version::V4,
        &BuildOpts { max_buffer_size: 64, ..BuildOpts::default() },
    )
    .unwrap();
    let huge_buf = build_fixture_bytes(
        Version::V4,
        &BuildOpts { max_buffer_size: 1 << 20, ..BuildOpts::default() },
    )
    .unwrap();
    gate(Version::V4, &tiny_buf);
    gate(Version::V4, &huge_buf);
    assert_eq!(tiny_buf, default_buf, "tiny buffer changed the bytes");
    assert_eq!(huge_buf, default_buf, "huge buffer changed the bytes");
}

#[test]
fn fixture_fixed_seed_build_is_byte_deterministic() {
    let first =
        build_fixture_bytes(Version::V3, &BuildOpts::default()).unwrap();
    let second =
        build_fixture_bytes(Version::V3, &BuildOpts::default()).unwrap();
    assert_eq!(first, second, "same seed must give byte-identical output");
}

//===========================================================================//
// Tests: recoverable mid-run failure.

#[test]
fn fixture_recovers_from_mid_run_flush_failure() {
    // Inject one recoverable failure into the first save's flush, mid-run
    // (the scenario saves again afterwards).  The error surfaces through
    // the existing io layering, and the very same CompoundFile recovers.
    let opts = BuildOpts::default();
    let mut flaky = FlakyIo::failing_flush(1);
    let mut comp = create_fixture_comp(Version::V4, &opts, &mut flaky).unwrap();
    for group in ordered_groups(Version::V4, opts.order) {
        for step in group {
            apply_step(&mut comp, step).unwrap();
        }
    }
    add_rotation_entries(&mut comp).unwrap();
    let error = comp.flush().expect_err("injected flush failure must surface");
    assert_eq!(error.kind(), ErrorKind::Interrupted);
    assert!(error.to_string().contains("injected deterministic"));
    // Recover on the same object: retry the save, then finish the scenario.
    comp.flush().expect("flush retry must succeed after recovery");
    pin_timestamps(&mut comp).unwrap();
    comp.flush().unwrap();
    drop(comp);
    let recovered = flaky.into_bytes();

    // The recovered result carries no cache/counter/temp state from the
    // failed call: it is byte-identical to a never-failed build.
    let clean =
        build_fixture_bytes(Version::V4, &BuildOpts::default()).unwrap();
    assert_eq!(recovered, clean, "recovered build diverges from clean build");
    gate(Version::V4, &recovered);
}

#[test]
fn fixture_failed_write_is_discardable_and_reproducible() {
    // A mid-build write failure aborts the build; discarding the partial
    // state and rerunning the identical input yields the stable result.
    let limit = 20_000u64;
    let mut flaky = FlakyIo::failing_write(limit);
    let error = build_fixture(
        Version::V4,
        &BuildOpts::default(),
        &mut flaky,
    )
    .expect_err("write past the limit must fail");
    assert_eq!(error.kind(), ErrorKind::StorageFull);
    assert!(error.to_string().contains("injected deterministic"));

    // The failure is reproducible: identical input, identical error.
    let mut flaky2 = FlakyIo::failing_write(limit);
    let error2 = build_fixture(
        Version::V4,
        &BuildOpts::default(),
        &mut flaky2,
    )
    .expect_err("second run must fail identically");
    assert_eq!(error2.kind(), error.kind());
    assert_eq!(error2.to_string(), error.to_string());

    // And a clean rerun of the same logical input is unaffected by the
    // failed attempts (no shared/global state).
    let clean =
        build_fixture_bytes(Version::V4, &BuildOpts::default()).unwrap();
    gate(Version::V4, &clean);
    assert_eq!(structural_summary(&clean), PINNED_SUMMARY_V4);
}

//===========================================================================//
// Pinned structural summaries (normalized; internal numbering hidden).

#[test]
fn fixture_v3_summary_is_pinned() {
    let bytes =
        build_fixture_bytes(Version::V3, &BuildOpts::default()).unwrap();
    gate(Version::V3, &bytes);
    assert_eq!(structural_summary(&bytes), PINNED_SUMMARY_V3);
}

#[test]
fn fixture_v4_summary_is_pinned() {
    let bytes =
        build_fixture_bytes(Version::V4, &BuildOpts::default()).unwrap();
    gate(Version::V4, &bytes);
    assert_eq!(structural_summary(&bytes), PINNED_SUMMARY_V4);
}

const PINNED_SUMMARY_V3: &str = include_str!("deterministic_fixture/v3.summary.txt");
const PINNED_SUMMARY_V4: &str = include_str!("deterministic_fixture/v4.summary.txt");
