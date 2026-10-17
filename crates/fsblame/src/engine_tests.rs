//! [`Engine`] driven by synthetic ring records, a fake `writes` map and a recording sink.
//!
//! Times are explicit `CLOCK_BOOTTIME` nanoseconds handed to the engine; `/proc` is a fixture
//! tree per test, so lineage never depends on the host's processes.

use std::{
    fs,
    os::unix::fs::symlink,
    sync::atomic::{AtomicU32, Ordering},
};

use fsblame_abi::{ExecRec, ExitRec, ForkRec, FsRec, RecHeader};

use super::*;
use crate::{
    filter::FilterSpec,
    report::{ChangeDetail, Timestamp},
    roots::{Root, kernel_dev},
};

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000 * MS;
/// Time of the first record of a test.
const T0: u64 = 1_000 * SEC;
/// Device of the watched filesystem.
const DEV: u32 = kernel_dev(259, 2);

/// A process as a test stages it.
#[derive(Clone, Copy, Debug)]
struct Proc {
    tgid: u32,
    start_ns: u64,
    comm: &'static str,
}

const SH: Proc = Proc {
    tgid: 100,
    start_ns: 10 * SEC,
    comm: "sh",
};

fn comm(name: &str) -> [u8; 16] {
    let mut comm = [0; 16];
    comm[..name.len()].copy_from_slice(name.as_bytes());
    comm
}

fn header(kind: u16, op: u16, flags: u32, ts_ns: u64) -> RecHeader {
    RecHeader {
        kind,
        op,
        flags,
        ts_ns,
    }
}

fn len(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).unwrap()
}

/// The ring item of a fork of `child` by `parent`.
fn fork(ts_ns: u64, parent: Proc, child: Proc) -> Vec<u8> {
    let rec = ForkRec {
        hdr: header(abi::REC_FORK, 0, 0, ts_ns),
        parent_tgid: parent.tgid,
        child_tgid: child.tgid,
        child_start_ns: child.start_ns,
    };
    wire::as_bytes(&rec).to_vec()
}

/// The ring item of `p`'s exit.
fn exit(ts_ns: u64, p: Proc) -> Vec<u8> {
    let rec = ExitRec {
        hdr: header(abi::REC_EXIT, 0, 0, ts_ns),
        tgid: p.tgid,
        code: 0,
        start_ns: p.start_ns,
    };
    wire::as_bytes(&rec).to_vec()
}

/// The ring item of an exec by `p` of `/usr/bin/<comm>` with `argv` (NUL-terminated
/// arguments), its parent at exec time `ppid`, and the cwd `names` (leaf first) when the
/// kernel captured them.
fn exec(ts_ns: u64, p: Proc, ppid: u32, argv: &[u8], cwd: Option<&[u8]>) -> Vec<u8> {
    let filename = format!("/usr/bin/{}\0", p.comm);
    let cwd_names = cwd.unwrap_or_default();
    let rec = ExecRec {
        hdr: header(
            abi::REC_EXEC,
            0,
            if cwd.is_some() { abi::F_CWD } else { 0 },
            ts_ns,
        ),
        tgid: p.tgid,
        ppid,
        start_ns: p.start_ns,
        cgroup_id: 0,
        uid: 1000,
        gid: 1000,
        comm: comm(p.comm),
        filename_len: len(filename.as_bytes()),
        env_len: 0,
        argv_len: len(argv),
        cwd_len: len(cwd_names),
    };
    [wire::as_bytes(&rec), filename.as_bytes(), argv, cwd_names].concat()
}

/// A file operation by `p` on inode `ino`, named `/w/f<ino>`; tests set the op-specific
/// fields.
fn fs_rec(op: u16, ts_ns: u64, p: Proc, ino: u64) -> FsRec {
    FsRec {
        hdr: header(abi::REC_FS, op, 0, ts_ns),
        tgid: p.tgid,
        tid: p.tgid,
        ns_tgid: 0,
        _pad: 0,
        start_ns: p.start_ns,
        comm: comm(p.comm),
        uid: 1000,
        dev: DEV,
        ino,
        mode: 0o100_644,
        root: 0,
        root2: abi::ROOT_NONE,
        path_len: 0,
        path2_len: 0,
        aux: 0,
        aux2: 0,
        bytes: 0,
        file: 0,
    }
}

/// The first write of `bytes` by `p` to inode `ino` through the `struct file` at `file`.
fn first_write(ts_ns: u64, p: Proc, file: u64, ino: u64, bytes: u64) -> FsRec {
    FsRec {
        bytes,
        file,
        ..fs_rec(abi::OP_WRITE, ts_ns, p, ino)
    }
}

/// The ring item of `rec`, with its single path name `f<ino>` below root 0.
fn fs_item(rec: FsRec) -> Vec<u8> {
    fs_item_named(rec, &format!("f{}", rec.ino))
}

/// The dentry names of `path`, relative to a root, as the kernel reports them: leaf first,
/// each NUL-terminated.
fn names(path: &str) -> String {
    path.rsplit('/').flat_map(|name| [name, "\0"]).collect()
}

/// The ring item of `rec`, with the path `path` below root 0.
fn fs_item_named(mut rec: FsRec, path: &str) -> Vec<u8> {
    let names = names(path);
    rec.path_len = len(names.as_bytes());
    [wire::as_bytes(&rec), names.as_bytes()].concat()
}

/// The ring item of a rename by `p` of inode `ino` from `old` to `new` (paths below root 0)
/// with `flags`, over or exchanged with inode `other` (0 for none).
fn rename(
    ts_ns: u64,
    p: Proc,
    ino: u64,
    (old, new): (&str, &str),
    flags: u32,
    other: u64,
) -> Vec<u8> {
    let mut rec = fs_rec(abi::OP_RENAME, ts_ns, p, ino);
    rec.root2 = 0;
    (rec.aux, rec.aux2) = (u64::from(flags), other);
    let (new, old) = (names(new), names(old));
    rec.path_len = len(new.as_bytes());
    rec.path2_len = len(old.as_bytes());
    [wire::as_bytes(&rec), new.as_bytes(), old.as_bytes()].concat()
}

/// The first write of `bytes` through the `struct file` at `file`, which the kernel bound
/// anew for this open of it, handing over the final `(bytes, calls)` of the binding it
/// replaced.
fn replacing_write(
    ts_ns: u64,
    p: Proc,
    file: u64,
    ino: u64,
    bytes: u64,
    (old_bytes, old_calls): (u64, u64),
) -> FsRec {
    let mut rec = first_write(ts_ns, p, file, ino, bytes);
    rec.hdr.flags = abi::F_REPLACED;
    (rec.aux, rec.aux2) = (old_bytes, old_calls);
    rec
}

/// The kernel's `writes` map.
#[derive(Debug, Default)]
struct Kernel(HashMap<(u32, u64), WriteVal>);

impl Kernel {
    /// The binding of `p` and `file`, opened at `first_ns`, now totals `bytes` over `calls`
    /// writes, the latest at `last_ns`.
    fn set(&mut self, p: Proc, file: u64, first_ns: u64, (bytes, calls): (u64, u64), last_ns: u64) {
        let val = WriteVal {
            dev: DEV,
            _pad: 0,
            ino: 0,
            bytes,
            calls,
            first_ns,
            last_ns,
        };
        self.0.insert((p.tgid, file), val);
    }
}

impl Totals for Kernel {
    fn get(&self, key: &WriteKey) -> Option<WriteVal> {
        self.0.get(&(key.tgid, key.file)).copied()
    }

    fn remove(&mut self, key: &WriteKey) {
        self.0.remove(&(key.tgid, key.file));
    }
}

/// A sink keeping each line as a reader of the NDJSON output parses it.
#[derive(Debug, Default)]
struct Recorder(Vec<Line<'static>>);

impl Sink for Recorder {
    fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
        let json = serde_json::to_string(line)?;
        self.0.push(Line::parse(&json)?);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A fixture `/proc` tree, removed on drop.
#[derive(Debug)]
struct ProcDir(PathBuf);

impl ProcDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("fsblame-engine-{}-{id}", std::process::id())))
    }
}

impl Drop for ProcDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// An engine watching `/w` (root 0), with its kernel map, clock and `/proc` fixture.
struct Harness {
    engine: Engine<Recorder>,
    kernel: Kernel,
    clock: Clock,
    proc_dir: ProcDir,
}

impl Harness {
    fn new() -> Self {
        Self::filtered(FilterSpec::default())
    }

    fn filtered(spec: FilterSpec) -> Self {
        let roots = Roots::from_entries(vec![Root {
            path: PathBuf::from("/w"),
            exclude: false,
            nested: false,
            dev: DEV,
            ino: 2,
            fstype: "ext4".into(),
        }]);
        let clock = Clock::new();
        let proc_dir = ProcDir::new();
        let mut engine = Engine::new(roots, clock, Filter::new(spec), Recorder::default());
        // Processes come from the fixture tree, never from the host's /proc.
        let procfs = ProcFs::with_roots(proc_dir.0.join("proc"), proc_dir.0.join("cgroup"));
        let cfg = Config {
            start_clock: engine.start_clock,
            ..Config::default()
        };
        engine.procs = ProcTable::new(procfs, cfg);
        Self {
            engine,
            kernel: Kernel::default(),
            clock,
            proc_dir,
        }
    }

    fn feed(&mut self, item: &[u8]) {
        self.engine.handle(item, &mut self.kernel).unwrap();
    }

    fn poll(&mut self, now_ns: u64) {
        self.engine.poll(now_ns, &mut self.kernel).unwrap();
    }

    fn finish(&mut self) {
        self.engine.finish(&mut self.kernel).unwrap();
    }

    /// Takes the changes reported so far.
    fn touches(&mut self) -> Vec<ChangeReport<'static>> {
        self.engine
            .sink_mut()
            .0
            .drain(..)
            .map(|line| match line {
                Line::Touch(touch) => touch,
                other => panic!("not a touch: {other:?}"),
            })
            .collect()
    }

    /// Stages `/proc/<pid>` of the live process `p`, whose cwd is `cwd`.
    fn proc_entry(&self, p: Proc, cwd: &str) {
        let dir = self.proc_dir.0.join("proc").join(p.tgid.to_string());
        fs::create_dir_all(&dir).unwrap();
        let (pid, comm) = (p.tgid, p.comm);
        let ticks = self.engine.start_clock.start_to_ticks(p.start_ns);
        let stat =
            format!("{pid} ({comm}) S 0 {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n");
        fs::write(dir.join("stat"), stat).unwrap();
        symlink(cwd, dir.join("cwd")).unwrap();
    }

    /// The report time of the event time `boot_ns`, to the microsecond as lines carry it.
    fn ts(&self, boot_ns: u64) -> Timestamp {
        let unix_ns = Timestamp::from_boot(self.clock, boot_ns).unix_ns();
        Timestamp::from_unix_ns(unix_ns - unix_ns.rem_euclid(1000))
    }
}

/// `(bytes, calls)` of a write window.
fn window(touch: &ChangeReport<'_>) -> (u64, u64) {
    assert_eq!(touch.op, Op::Write, "{touch:?}");
    (touch.bytes.unwrap(), touch.calls.unwrap())
}

/// Path and `(bytes, calls)` of each write window, sorted by path.
fn windows_by_path(touches: &[ChangeReport<'_>]) -> Vec<(String, (u64, u64))> {
    let mut windows: Vec<_> = touches
        .iter()
        .map(|t| (t.path.to_string(), window(t)))
        .collect();
    windows.sort();
    windows
}

#[test]
fn write_window_is_reported_after_200ms_quiet_and_the_next_one_carries_only_its_own_writes() {
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xf1, 7, 10)));
    h.kernel.set(SH, 0xf1, T0, (30, 3), T0 + 50 * MS);
    for ms in [100, 200] {
        h.poll(T0 + ms * MS);
        assert!(h.touches().is_empty(), "reported at {ms} ms, too soon");
    }
    h.poll(T0 + 300 * MS);
    let [touch] = &h.touches()[..] else {
        panic!("one window");
    };
    assert_eq!(touch.path, "/w/f7");
    assert_eq!(window(touch), (30, 3));
    assert_eq!(
        touch.ts,
        h.ts(T0 + 50 * MS),
        "stamped with the latest write"
    );

    h.kernel.set(SH, 0xf1, T0, (80, 5), T0 + 400 * MS);
    for ms in [400, 500] {
        h.poll(T0 + ms * MS);
        assert!(h.touches().is_empty(), "reported at {ms} ms, too soon");
    }
    h.poll(T0 + 600 * MS);
    let [touch] = &h.touches()[..] else {
        panic!("one window");
    };
    assert_eq!(window(touch), (50, 2));
    assert_eq!(touch.ts, h.ts(T0 + 400 * MS));
}

#[test]
fn continuous_writes_are_reported_once_a_second_without_losing_any() {
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xf1, 7, 10)));
    let mut reports = Vec::new();
    for k in 1..=21 {
        let now = T0 + k * 100 * MS;
        // One more write of 10 bytes just before every poll: never quiet.
        h.kernel.set(SH, 0xf1, T0, (10 * (k + 1), k + 1), now - MS);
        h.poll(now);
        reports.extend(h.touches().iter().map(|t| (k, window(t), t.ts)));
    }
    // The first window opened at the first write; the second at the first poll that saw a
    // write after the first report (1.1 s).
    assert_eq!(
        reports,
        [
            (10, (110, 11), h.ts(T0 + 999 * MS)),
            (21, (110, 11), h.ts(T0 + 2_099 * MS)),
        ]
    );
}

#[test]
fn exit_reports_pending_writes_while_the_process_is_still_live() {
    let mut h = Harness::new();
    h.feed(&exec(T0, SH, 0, b"sh\0-c\0echo x >> f7\0", None));
    h.feed(&fs_item(first_write(T0 + MS, SH, 0xf1, 7, 2)));
    h.kernel.set(SH, 0xf1, T0 + MS, (4, 2), T0 + 2 * MS);
    h.feed(&exit(T0 + 3 * MS, SH));
    let [touch] = &h.touches()[..] else {
        panic!("one window");
    };
    assert_eq!(window(touch), (4, 2));
    assert_eq!(
        touch.proc.exited,
        Some(false),
        "reported before the exit was recorded"
    );
    assert_eq!(touch.proc.argv, ["sh", "-c", "echo x >> f7"]);
    assert!(
        h.kernel.0.is_empty(),
        "the exited process's bindings leave the map"
    );
    h.finish();
    assert!(h.touches().is_empty(), "the binding is forgotten");
}

#[test]
fn exec_reports_pending_writes_of_the_image_it_replaces() {
    let mut h = Harness::new();
    h.feed(&exec(T0, SH, 0, b"sh\0-c\0echo x >> f7; mkdir f8\0", None));
    h.feed(&fs_item(first_write(T0 + MS, SH, 0xf1, 7, 2)));
    h.kernel.set(SH, 0xf1, T0 + MS, (2, 1), T0 + MS);
    // sh runs its last command in place.
    let mkdir = Proc {
        comm: "mkdir",
        ..SH
    };
    h.feed(&exec(T0 + 2 * MS, mkdir, 0, b"mkdir\0f8\0", None));
    h.feed(&fs_item(fs_rec(abi::OP_MKDIR, T0 + 3 * MS, mkdir, 8)));
    let touches = h.touches();
    let [written, created] = &touches[..] else {
        panic!("a write and a mkdir: {touches:?}");
    };
    assert_eq!(window(written), (2, 1));
    assert_eq!(written.proc.comm, "sh");
    assert_eq!(written.proc.argv, ["sh", "-c", "echo x >> f7; mkdir f8"]);
    assert_eq!(created.op, Op::Mkdir);
    assert_eq!(created.proc.comm, "mkdir");

    // The descriptor survives the exec: later writes through it are still counted, once.
    h.kernel.set(SH, 0xf1, T0 + MS, (5, 2), T0 + 4 * MS);
    h.finish();
    let [later] = &h.touches()[..] else {
        panic!("one window");
    };
    assert_eq!(window(later), (3, 1));
}

#[test]
fn finish_reports_every_pending_window_once() {
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xf1, 7, 10)));
    h.kernel.set(SH, 0xf1, T0, (25, 2), T0 + MS);
    h.finish();
    let [touch] = &h.touches()[..] else {
        panic!("one window");
    };
    assert_eq!(window(touch), (25, 2));
    h.finish();
    assert_eq!(h.touches(), []);
}

#[test]
fn reused_struct_file_hands_the_old_binding_totals_over() {
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xf1, 7, 10)));
    h.kernel.set(SH, 0xf1, T0, (20, 2), T0 + 10 * MS);
    h.poll(T0 + 100 * MS);
    assert_eq!(h.touches(), []);
    // One more write, then the file is closed and its struct file reused for inode 9: the
    // kernel replaced the binding and handed the old one's final totals over.
    h.feed(&fs_item(replacing_write(
        T0 + 150 * MS,
        SH,
        0xf1,
        9,
        7,
        (30, 3),
    )));
    h.kernel.set(SH, 0xf1, T0 + 150 * MS, (7, 1), T0 + 150 * MS);
    assert!(h.touches().is_empty(), "both windows wait for quiet");
    h.poll(T0 + 400 * MS);
    assert_eq!(
        windows_by_path(&h.touches()),
        [("/w/f7".to_owned(), (30, 3)), ("/w/f9".to_owned(), (7, 1))]
    );
    assert_eq!(h.engine.counts().evicted, 0);
}

#[test]
fn only_bindings_the_lru_dropped_count_as_evicted() {
    let mut h = Harness::new();
    for file in 1..=3 {
        h.feed(&fs_item(first_write(T0, SH, file, file, 10)));
    }
    h.kernel.set(SH, 1, T0, (10, 1), T0);
    // File 2's binding was evicted; file 3's was superseded by a newer binding whose record
    // is still in the ring.
    h.kernel.set(SH, 3, T0 + 50 * MS, (5, 1), T0 + 50 * MS);
    h.poll(T0 + 100 * MS);
    assert_eq!(h.engine.counts().evicted, 1);
    // That record hands file 3's final totals over: nothing is lost.
    h.feed(&fs_item(replacing_write(
        T0 + 50 * MS,
        SH,
        3,
        3,
        5,
        (12, 2),
    )));
    // A first write for a binding the engine holds, without F_REPLACED: the kernel had no
    // binding left to replace.
    h.feed(&fs_item(first_write(T0 + 150 * MS, SH, 1, 1, 4)));
    assert_eq!(h.engine.counts().evicted, 2);
    // What was seen of each binding is still reported, the lost one's with the writes
    // that followed it.
    h.kernel.set(SH, 1, T0 + 150 * MS, (4, 1), T0 + 150 * MS);
    h.poll(T0 + 400 * MS);
    assert_eq!(
        windows_by_path(&h.touches()),
        [
            ("/w/f1".to_owned(), (14, 2)),
            ("/w/f2".to_owned(), (10, 1)),
            ("/w/f3".to_owned(), (17, 3)),
        ]
    );
    assert_eq!(h.engine.counts().evicted, 2);
}

#[test]
fn a_superseded_binding_waits_for_the_record_with_its_final_totals() {
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xf1, 7, 10)));
    h.kernel.set(SH, 0xf1, T0, (35, 4), T0 + 50 * MS);
    h.poll(T0 + 100 * MS);
    // Two more writes, then the file is closed and its struct file reused for inode 9: the
    // next poll finds the new binding before the record of it is read.
    h.kernel.set(SH, 0xf1, T0 + 250 * MS, (7, 1), T0 + 250 * MS);
    h.poll(T0 + 400 * MS);
    assert_eq!(h.touches(), [], "f7's window waits for its final totals");
    h.feed(&fs_item(replacing_write(
        T0 + 250 * MS,
        SH,
        0xf1,
        9,
        7,
        (55, 6),
    )));
    h.poll(T0 + 500 * MS);
    assert_eq!(
        windows_by_path(&h.touches()),
        [("/w/f7".to_owned(), (55, 6)), ("/w/f9".to_owned(), (7, 1))]
    );
    assert_eq!(h.engine.counts().evicted, 0);
}

#[test]
fn superseded_bindings_whose_record_was_lost_count_as_evicted() {
    let mut h = Harness::new();
    let cc = Proc {
        tgid: 300,
        start_ns: 30 * SEC,
        comm: "cc",
    };
    for p in [SH, cc] {
        h.feed(&fs_item(first_write(T0, p, 0xf1, 7, 10)));
        h.kernel.set(p, 0xf1, T0, (35, 4), T0 + 50 * MS);
    }
    h.poll(T0 + 100 * MS);
    // Each replaced its binding at 250 ms, and the records of that were dropped with the ring
    // full.
    for p in [SH, cc] {
        h.kernel.set(p, 0xf1, T0 + 250 * MS, (7, 1), T0 + 250 * MS);
    }
    h.poll(T0 + 400 * MS);
    assert_eq!(h.touches(), [], "the windows wait for their final totals");
    // The records of a process's writes come before its exit.
    h.feed(&exit(T0 + 500 * MS, cc));
    assert_eq!(h.engine.counts().evicted, 1);
    // The hold limit cuts the window of sh, whose record may still come...
    h.poll(T0 + 1_000 * MS);
    assert_eq!(h.engine.counts().evicted, 1);
    // ...until the ring has been read a second past the replacement.
    h.feed(&fs_item(fs_rec(abi::OP_UNLINK, T0 + 1_300 * MS, SH, 8)));
    h.poll(T0 + 1_300 * MS);
    assert_eq!(h.engine.counts().evicted, 2);
    let windows: Vec<_> = h
        .touches()
        .iter()
        .filter(|t| t.op == Op::Write)
        .map(|t| (t.comm.to_string(), window(t)))
        .collect();
    assert_eq!(
        windows,
        [("cc".to_owned(), (35, 4)), ("sh".to_owned(), (35, 4))]
    );
}

#[test]
fn a_record_replacing_a_later_binding_does_not_close_a_superseded_one() {
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xf1, 7, 10)));
    h.kernel.set(SH, 0xf1, T0, (35, 4), T0 + 50 * MS);
    h.poll(T0 + 100 * MS);
    // Replaced at 250 ms, a record that was dropped; the poll sees the replacement.
    h.kernel
        .set(SH, 0xf1, T0 + 250 * MS, (90, 9), T0 + 260 * MS);
    h.poll(T0 + 400 * MS);
    // Replaced again at 300 ms: this record hands over the totals of the unseen binding.
    h.feed(&fs_item(replacing_write(
        T0 + 300 * MS,
        SH,
        0xf1,
        9,
        2,
        (90, 9),
    )));
    assert_eq!(h.engine.counts().evicted, 1);
    h.kernel.set(SH, 0xf1, T0 + 300 * MS, (2, 1), T0 + 300 * MS);
    h.poll(T0 + 600 * MS);
    assert_eq!(
        windows_by_path(&h.touches()),
        [("/w/f7".to_owned(), (35, 4)), ("/w/f9".to_owned(), (2, 1))]
    );
}

#[test]
fn writes_through_a_descriptor_kept_across_a_rename_are_reported_at_the_new_name() {
    let mut h = Harness::new();
    let nginx = Proc {
        tgid: 200,
        start_ns: 20 * SEC,
        comm: "nginx",
    };
    let logrotate = Proc {
        tgid: 300,
        start_ns: 30 * SEC,
        comm: "logrotate",
    };
    h.feed(&fs_item_named(
        first_write(T0, nginx, 0xf1, 7, 10),
        "access.log",
    ));
    h.kernel.set(nginx, 0xf1, T0, (30, 3), T0 + 50 * MS);
    // `mv access.log access.log.1` while nginx keeps its descriptor.
    h.feed(&rename(
        T0 + 100 * MS,
        logrotate,
        7,
        ("access.log", "access.log.1"),
        0,
        0,
    ));
    let touches = h.touches();
    let [written, renamed] = &touches[..] else {
        panic!("the pending window, then the rename: {touches:?}");
    };
    assert_eq!(
        (&*written.path, window(written)),
        ("/w/access.log", (30, 3))
    );
    assert_eq!(
        (renamed.op, &*renamed.path),
        (Op::Rename, "/w/access.log.1")
    );

    h.kernel.set(nginx, 0xf1, T0, (50, 5), T0 + 150 * MS);
    for ms in [200, 300, 400] {
        h.poll(T0 + ms * MS);
    }
    let [touch] = &h.touches()[..] else {
        panic!("one window");
    };
    assert_eq!((&*touch.path, window(touch)), ("/w/access.log.1", (20, 2)));
}

#[test]
fn renamed_directories_and_exchanged_files_carry_their_open_files_along() {
    let mut h = Harness::new();
    let mv = Proc {
        tgid: 300,
        start_ns: 30 * SEC,
        comm: "mv",
    };
    let files = [(0xa, 9, "logs/app.log"), (0xb, 7, "x"), (0xc, 8, "y")];
    for (file, ino, path) in files {
        h.feed(&fs_item_named(first_write(T0, SH, file, ino, 1), path));
        h.kernel.set(SH, file, T0, (1, 1), T0);
    }
    // `mv logs logs.old` (inode 5), then `mv --exchange x y`.
    h.feed(&rename(T0 + 10 * MS, mv, 5, ("logs", "logs.old"), 0, 0));
    h.feed(&rename(T0 + 20 * MS, mv, 7, ("x", "y"), RENAME_EXCHANGE, 8));
    for (file, _, _) in files {
        h.kernel.set(SH, file, T0, (3, 2), T0 + 30 * MS);
    }
    h.finish();
    let mut windows: Vec<_> = h
        .touches()
        .iter()
        .filter(|t| t.op == Op::Write)
        .map(|t| (t.path.to_string(), t.file.ino, window(t)))
        .collect();
    windows.sort();
    let at = |path: &str, ino, window| (format!("/w/{path}"), ino, window);
    assert_eq!(
        windows,
        [
            at("logs.old/app.log", 9, (2, 1)),
            at("logs/app.log", 9, (1, 1)),
            at("x", 7, (1, 1)),
            at("x", 8, (2, 1)),
            at("y", 7, (2, 1)),
            at("y", 8, (1, 1)),
        ]
    );
}

#[test]
fn writes_after_an_exec_through_an_inherited_descriptor_are_the_new_programs() {
    let mut h = Harness::filtered(FilterSpec {
        comm: vec!["make".into()],
        ..FilterSpec::default()
    });
    // `sh -c 'echo building; exec make' >> build.log`
    h.feed(&exec(
        T0,
        SH,
        0,
        b"sh\0-c\0echo building; exec make\0",
        None,
    ));
    h.feed(&fs_item_named(
        first_write(T0 + MS, SH, 0xf1, 7, 9),
        "build.log",
    ));
    h.kernel.set(SH, 0xf1, T0 + MS, (9, 1), T0 + MS);
    let make = Proc { comm: "make", ..SH };
    h.feed(&exec(T0 + 2 * MS, make, 0, b"make\0", None));
    assert_eq!(h.touches(), [], "sh's write is not make's");
    h.kernel.set(SH, 0xf1, T0 + MS, (29, 3), T0 + 3 * MS);
    h.finish();
    let [touch] = &h.touches()[..] else {
        panic!("make's writes");
    };
    assert_eq!((&*touch.comm, window(touch)), ("make", (20, 2)));
}

#[test]
fn lines_after_a_wall_clock_step_keep_the_offset_of_their_events_time() {
    const HOUR: i128 = 3_600 * 1_000_000_000;
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xf1, 7, 10)));
    h.kernel.set(SH, 0xf1, T0, (10, 1), T0);
    // Sampled at 100 ms; by 200 ms NTP's first sync has set the clock an hour ahead.
    let offset = h.clock.unix_ns(T0) - i128::from(T0);
    let mut clock = Clock::at(T0 + 100 * MS, offset);
    clock.update(T0 + 200 * MS, offset + HOUR, 0);
    h.engine.set_clock(clock);
    h.feed(&fs_item(fs_rec(abi::OP_UNLINK, T0 + 250 * MS, SH, 7)));
    let touches = h.touches();
    let [written, unlinked] = &touches[..] else {
        panic!("the pending window, then the unlink: {touches:?}");
    };
    assert_eq!(written.ts, h.ts(T0), "written before the step");
    assert_eq!(
        unlinked.ts.unix_ns() - written.ts.unix_ns(),
        HOUR + i128::from(250 * MS),
        "unlinked after it"
    );
}

#[test]
fn reopening_one_file_over_and_over_reports_one_window() {
    let mut h = Harness::new();
    // A logger opens the file, appends k + 1 bytes and closes it, 300 times within 90 ms;
    // the slab hands the same struct file back every time.
    let mut last = (0, 0);
    for k in 0..300 {
        let ts = T0 + k * 300_000;
        let bytes = k + 1;
        let rec = if k == 0 {
            first_write(ts, SH, 0xf1, 7, bytes)
        } else {
            replacing_write(ts, SH, 0xf1, 7, bytes, last)
        };
        h.feed(&fs_item(rec));
        h.kernel.set(SH, 0xf1, ts, (bytes, 1), ts);
        last = (bytes, 1);
    }
    h.poll(T0 + 100 * MS);
    assert!(h.touches().is_empty(), "still writing 10 ms ago");
    h.poll(T0 + 300 * MS);
    let [touch] = &h.touches()[..] else {
        panic!("one window");
    };
    assert_eq!(touch.path, "/w/f7");
    assert_eq!(window(touch), (300 * 301 / 2, 300));
    assert_eq!(touch.ts, h.ts(T0 + 299 * 300_000));
}

#[test]
fn distinct_files_behind_a_recycled_struct_file_and_inode_number_stay_apart() {
    let mut h = Harness::new();
    // 300 files created, written and deleted in turn: each gets the freed struct file and
    // the freed inode number back, but is another file under another name.
    let mut last = (0, 0);
    for k in 0..300 {
        let ts = T0 + k * 300_000;
        let rec = if k == 0 {
            first_write(ts, SH, 0xf1, 7, 1)
        } else {
            replacing_write(ts, SH, 0xf1, 7, 1, last)
        };
        h.feed(&fs_item_named(rec, &format!("tmp{k}")));
        h.kernel.set(SH, 0xf1, ts, (1, 1), ts);
        last = (1, 1);
    }
    h.finish();
    let reported: Vec<_> = h
        .touches()
        .iter()
        .map(|t| (t.path.to_string(), window(t)))
        .collect();
    let expected: Vec<_> = (0..300).map(|k| (format!("/w/tmp{k}"), (1, 1))).collect();
    assert_eq!(reported, expected);
}

#[test]
fn reopened_file_windows_are_still_cut_at_the_hold_limit() {
    let mut h = Harness::new();
    // An open, append and close every 50 ms for 2.5 s, polled after each.
    let mut last = (0, 0);
    let mut reports = Vec::new();
    for k in 0..50 {
        let ts = T0 + k * 50 * MS;
        let rec = if k == 0 {
            first_write(ts, SH, 0xf1, 7, 2)
        } else {
            replacing_write(ts, SH, 0xf1, 7, 2, last)
        };
        h.feed(&fs_item(rec));
        h.kernel.set(SH, 0xf1, ts, (2, 1), ts);
        last = (2, 1);
        h.poll(ts);
        reports.extend(h.touches().iter().map(|t| (k, window(t), t.ts)));
    }
    h.finish();
    reports.extend(h.touches().iter().map(|t| (50, window(t), t.ts)));
    // Held 1 s: the first window takes the opens at 0..=1000 ms, the second those at
    // 1050..=2050 ms, and stopping reports the rest.
    assert_eq!(
        reports,
        [
            (20, (42, 21), h.ts(T0 + 1_000 * MS)),
            (41, (42, 21), h.ts(T0 + 2_050 * MS)),
            (50, (16, 8), h.ts(T0 + 2_450 * MS)),
        ]
    );
}

#[test]
fn mapped_write_reports_the_files_pending_writes_first() {
    let mut h = Harness::new();
    h.feed(&fs_item(first_write(T0, SH, 0xa, 7, 100)));
    h.kernel.set(SH, 0xa, T0, (300, 3), T0 + 5 * MS);
    h.feed(&fs_item(first_write(T0, SH, 0xb, 8, 1)));
    h.kernel.set(SH, 0xb, T0, (1, 1), T0);
    let mut rec = fs_rec(abi::OP_WRITE, T0 + 10 * MS, SH, 7);
    rec.hdr.flags = abi::F_MAPPED;
    rec.aux = abi::MAP_VIA_MMAP;
    rec.file = 0xc;
    h.feed(&fs_item(rec));
    let touches = h.touches();
    let [written, mapped] = &touches[..] else {
        panic!("the pending window, then the mapping: {touches:?}");
    };
    assert_eq!(written.path, "/w/f7");
    assert_eq!(window(written), (300, 3));
    assert_eq!(mapped.op, Op::Write);
    assert_eq!(mapped.path, "/w/f7");
    assert_eq!((mapped.bytes, mapped.calls), (None, None));
    assert_eq!(
        mapped.change,
        Some(ChangeDetail {
            mapped: Some(MapVia::Mmap),
            ..ChangeDetail::default()
        })
    );
    assert_eq!(mapped.ts, h.ts(T0 + 10 * MS));

    rec.aux = 99;
    h.feed(&fs_item(rec));
    assert!(h.touches().is_empty(), "unknown MAP_VIA code");
    assert_eq!(h.engine.counts().malformed, 1);

    // The other file's window stayed pending, and the mapping opened none.
    h.finish();
    let [other] = &h.touches()[..] else {
        panic!("the other file's window");
    };
    assert_eq!(other.path, "/w/f8");
    assert_eq!(window(other), (1, 1));
}

#[test]
fn filtered_changes_are_neither_reported_nor_counted() {
    let mut h = Harness::filtered(FilterSpec {
        comm: vec!["make".into()],
        ..FilterSpec::default()
    });
    let vim = Proc {
        tgid: 200,
        start_ns: 20 * SEC,
        comm: "vim",
    };
    let make = Proc {
        tgid: 300,
        start_ns: 30 * SEC,
        comm: "make",
    };
    let mut chmod = fs_rec(abi::OP_CHMOD, T0, vim, 7);
    chmod.aux2 = 0o600;
    h.feed(&fs_item(chmod));
    h.feed(&fs_item(first_write(T0, vim, 0xa, 8, 5)));
    h.kernel.set(vim, 0xa, T0, (5, 1), T0);
    h.feed(&fs_item(fs_rec(abi::OP_UNLINK, T0 + MS, make, 9)));
    h.finish();
    let [touch] = &h.touches()[..] else {
        panic!("only make's change");
    };
    assert_eq!((touch.op, &*touch.comm), (Op::Unlink, "make"));
    assert_eq!(h.engine.counts().touches, 1);
}

#[test]
fn exec_cwd_from_the_kernel_wins_and_proc_is_the_fallback() {
    let mut h = Harness::new();
    let with_cwd = Proc {
        tgid: 300,
        start_ns: 30 * SEC,
        comm: "cc",
    };
    let staged = Proc {
        tgid: 400,
        start_ns: 40 * SEC,
        comm: "ld",
    };
    let unknown = Proc {
        tgid: 500,
        start_ns: 50 * SEC,
        comm: "as",
    };
    h.proc_entry(with_cwd, "/from/proc");
    h.proc_entry(staged, "/srv/build");
    h.feed(&exec(T0, with_cwd, 0, b"cc\0", Some(b"proj\0u\0home\0")));
    h.feed(&exec(T0, staged, 0, b"ld\0", None));
    h.feed(&exec(T0, unknown, 0, b"as\0", None));
    for (ino, p) in (10..).zip([with_cwd, staged, unknown]) {
        h.feed(&fs_item(fs_rec(abi::OP_UNLINK, T0 + MS, p, ino)));
    }
    let cwds: Vec<_> = h
        .touches()
        .iter()
        .map(|t| t.proc.cwd.as_deref().map(str::to_owned))
        .collect();
    assert_eq!(
        cwds,
        [
            Some("/home/u/proj".to_owned()),
            Some("/srv/build".to_owned()),
            None
        ]
    );
}

#[test]
fn fork_parent_wins_over_the_exec_parent() {
    let mut h = Harness::new();
    let init = Proc {
        tgid: 1,
        start_ns: SEC,
        comm: "init",
    };
    let make = Proc {
        tgid: 100,
        start_ns: 10 * SEC,
        comm: "make",
    };
    let cc = Proc {
        tgid: 300,
        start_ns: 30 * SEC,
        comm: "cc",
    };
    let ld = Proc {
        tgid: 400,
        start_ns: 40 * SEC,
        comm: "ld",
    };
    h.feed(&exec(T0, init, 0, b"init\0", None));
    h.feed(&exec(T0, make, init.tgid, b"make\0", None));
    // ld was forked before fsblame started: its exec's parent is all there is.
    h.feed(&exec(T0 + MS, ld, make.tgid, b"ld\0", None));
    // make forks cc and exits before cc's exec, which names the reaper as the parent.
    h.feed(&fork(T0 + 2 * MS, make, cc));
    h.feed(&exit(T0 + 3 * MS, make));
    h.feed(&exec(T0 + 4 * MS, cc, init.tgid, b"cc\0", None));
    for (ino, p) in (10..).zip([cc, ld]) {
        h.feed(&fs_item(fs_rec(abi::OP_UNLINK, T0 + 5 * MS, p, ino)));
    }
    let chains: Vec<(Vec<u32>, bool)> = h
        .touches()
        .iter()
        .map(|t| (t.chain().map(|p| p.pid).collect(), t.ancestry_complete))
        .collect();
    assert_eq!(
        chains,
        [(vec![300, 100, 1], true), (vec![400, 100, 1], true)]
    );
}
