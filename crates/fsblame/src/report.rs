//! The report model: every line fsblame outputs, as one value that each output format renders.
//!
//! The human tree view ([`crate::render::Human`]) and NDJSON ([`crate::render::Json`]) are
//! both rendered from a [`Line`], and NDJSON parses back into one, so a journal of lines
//! replays into the same tree view. Lines built live borrow their text from the touch and
//! lineage they describe; parsed lines own it.
//!
//! Each line is one JSON object with a `type` (`touch`, `lost` or `summary`) and the schema
//! version `v` ([`VERSION`]). Within a version, fields are only ever added; readers ignore
//! fields they do not know.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    fmt, io,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use procctx::{Confidence, OriginKind, ProcInfo};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{
    clock::{self, Clock},
    engine::{Actor, Change, Lineage, MapVia, RENAME_EXCHANGE, RENAME_NOREPLACE, Touch},
    filter::Candidate,
    ops::Op,
};

/// The schema version of every line, its `v` field.
pub const VERSION: u32 = 1;

/// Most groups a [`Summary`] keeps apart; changes of further groups count as
/// [`Group::Other`].
const SUMMARY_GROUPS: usize = 32;
/// Distinct paths a group remembers for counting; changes to further paths count as
/// [`GroupReport::paths_untracked`].
const SUMMARY_PATHS: usize = 1024;
/// Paths a group lists by name.
const SUMMARY_FIRST_PATHS: usize = 3;

/// Where report lines go.
pub trait Sink {
    /// Writes one line.
    fn line(&mut self, line: &Line<'_>) -> io::Result<()>;
    /// Flushes buffered output.
    fn flush(&mut self) -> io::Result<()>;
}

impl<S: Sink + ?Sized> Sink for &mut S {
    fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
        (**self).line(line)
    }

    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }
}

/// One output line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[allow(
    clippy::large_enum_variant,
    reason = "lines are built one at a time and passed by reference; boxing a change would \
              cost an allocation per change"
)]
pub enum Line<'a> {
    /// One reported change.
    Touch(ChangeReport<'a>),
    /// Records or totals the kernel side could not deliver.
    Lost(LostReport),
    /// What a run reported, grouped by build step or command.
    Summary(SummaryReport<'a>),
}

impl Line<'static> {
    /// Parses one NDJSON line. Fails for another schema version.
    pub fn parse(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

/// The `v` field: always [`VERSION`]; a line of another version does not parse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Version;

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(VERSION)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = u32::deserialize(deserializer)?;
        if v == VERSION {
            Ok(Self)
        } else {
            Err(D::Error::custom(format_args!(
                "report version {v} is not supported (this fsblame reads version {VERSION})"
            )))
        }
    }
}

/// Deserializes a string and converts it with `parse`; `what` names the expected form in
/// the error.
fn parse_str<'de, D: Deserializer<'de>, T>(
    deserializer: D,
    what: &str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<T, D::Error> {
    let text = Cow::<str>::deserialize(deserializer)?;
    parse(&text).ok_or_else(|| D::Error::custom(format_args!("{text:?} is not {what}")))
}

/// A wall-clock time, written as RFC 3339 UTC with microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i128);

impl Timestamp {
    /// The wall-clock time of an event timestamp (`CLOCK_BOOTTIME` ns).
    pub fn from_boot(clock: Clock, boot_ns: u64) -> Self {
        Self(clock.unix_ns(boot_ns))
    }

    /// The time `unix_ns` nanoseconds after the Unix epoch.
    pub const fn from_unix_ns(unix_ns: i128) -> Self {
        Self(unix_ns)
    }

    /// Nanoseconds since the Unix epoch.
    pub const fn unix_ns(self) -> i128 {
        self.0
    }

    /// Local `HH:MM:SS`.
    pub fn local_hms(self) -> String {
        clock::local_hms(self.0)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&clock::Rfc3339(self.0))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_str(deserializer, "an RFC 3339 time", clock::parse_rfc3339).map(Self)
    }
}

/// A kernel device number (`dev_t`), written `MAJOR:MINOR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dev(pub u32);

impl fmt::Display for Dev {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.0 >> 20, self.0 & 0xf_ffff)
    }
}

impl Serialize for Dev {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Dev {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_str(deserializer, "a MAJOR:MINOR device number", |text| {
            let (major, minor) = text.split_once(':')?;
            let (major, minor): (u32, u32) = (major.parse().ok()?, minor.parse().ok()?);
            (major < 1 << 12 && minor < 1 << 20).then_some(Self(major << 20 | minor))
        })
    }
}

/// A whole `i_mode` (type and permission bits), written in octal, such as `100644`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileMode(pub u32);

impl Serialize for FileMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:o}", self.0))
    }
}

impl<'de> Deserialize<'de> for FileMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_str(deserializer, "an octal file mode", |text| {
            u32::from_str_radix(text, 8).ok().map(Self)
        })
    }
}

/// Permission bits, written as four octal digits, such as `0644`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Perms(pub u32);

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0 & 0o7777)
    }
}

impl Serialize for Perms {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Perms {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_str(deserializer, "octal permissions", |text| {
            u32::from_str_radix(text, 8)
                .ok()
                .filter(|mode| *mode <= 0o7777)
                .map(Self)
        })
    }
}

/// [`Op`] as its [`name`](Op::name).
mod op_name {
    use serde::{Deserializer, Serializer};

    use super::{Op, parse_str};

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "the signature serde's `with` requires"
    )]
    pub fn serialize<S: Serializer>(op: &Op, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(op.name())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Op, D::Error> {
        parse_str(deserializer, "an operation", |name| {
            Op::ALL.into_iter().find(|op| op.name() == name)
        })
    }
}

/// The position of `op` in [`Op::ALL`].
fn op_index(op: Op) -> usize {
    Op::ALL
        .iter()
        .position(|&o| o == op)
        .expect("Op::ALL lists every op")
}

/// One reported change: `{"type":"touch",...}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeReport<'a> {
    /// Schema version.
    pub v: Version,
    /// When it happened; for writes, the latest write of the window.
    pub ts: Timestamp,
    /// Operation.
    #[serde(with = "op_name")]
    pub op: Op,
    /// Affected path (for renames the new name, for links the new link).
    pub path: Cow<'a, str>,
    /// Rename source.
    pub old_path: Option<Cow<'a, str>>,
    /// Symlink target (as stored), or the existing name a hard link points at.
    pub target: Option<Cow<'a, str>>,
    /// Some upper components of a path were lost to the kernel walk limits.
    pub truncated: bool,
    /// Bytes requested by the write calls of a write window.
    pub bytes: Option<u64>,
    /// Write calls of a write window.
    pub calls: Option<u64>,
    /// File identity and mode.
    pub file: FileReport,
    /// Op-specific detail; `null` when there is none (writes carry `bytes`/`calls`).
    pub change: Option<ChangeDetail>,
    /// Acting thread.
    pub tid: u32,
    /// The acting thread's `comm`, as the kernel saw it at the operation.
    pub comm: Cow<'a, str>,
    /// The actor's real uid at the operation.
    pub uid: u32,
    /// The actor's process id in its own pid namespace, when that is not the initial one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ns_pid: Option<u32>,
    /// The acting process.
    pub proc: ProcReport<'a>,
    /// Its ancestors, parent first.
    pub ancestry: Vec<ProcReport<'a>>,
    /// The ancestry reached a root rather than an unknown process.
    pub ancestry_complete: bool,
    /// cgroup, systemd unit, container and tmux pane.
    pub context: ContextReport<'a>,
    /// The build step the actor runs under.
    pub origin: Option<OriginReport<'a>>,
    /// Which lineage the fields from `proc` to `origin` describe, for sinks that reuse what
    /// they made of it; not part of the line. `None` for a parsed line or an unknown actor.
    #[serde(skip)]
    pub lineage: Option<LineageId>,
}

/// Identifies a lineage: touch reports with the same id ([`ChangeReport::lineage`]) have the
/// same fields from `proc` to `origin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LineageId(u64);

impl LineageId {
    /// An id no lineage of this process has had before.
    pub fn fresh() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

impl<'a> ChangeReport<'a> {
    /// The report of `touch`, made by the process with `lineage`, borrowing their text.
    pub fn new(touch: &'a Touch, lineage: &'a Lineage, clock: Clock) -> Self {
        let text = |path: &'a Path| path.to_string_lossy();
        let (bytes, calls) = match touch.change {
            Change::Write { bytes, calls } => (Some(bytes), Some(calls)),
            _ => (None, None),
        };
        let mut chain = lineage
            .chain
            .iter()
            .map(|info| ProcReport::new(info, clock));
        let proc = chain
            .next()
            .unwrap_or_else(|| ProcReport::untracked(&touch.actor));
        let ctx = &lineage.context;
        Self {
            v: Version,
            ts: Timestamp::from_boot(clock, touch.ts_ns),
            op: touch.op,
            path: text(&touch.path),
            old_path: touch.old_path.as_deref().map(text),
            target: touch.target.as_deref().map(text),
            truncated: touch.truncated,
            bytes,
            calls,
            file: FileReport {
                dev: Dev(touch.file.dev),
                ino: touch.file.ino,
                mode: FileMode(touch.mode),
            },
            change: ChangeDetail::of(touch),
            tid: touch.actor.tid,
            comm: Cow::Borrowed(touch.actor.comm.as_str()),
            uid: touch.actor.uid,
            ns_pid: touch.actor.ns_tgid,
            proc,
            ancestry: chain.collect(),
            ancestry_complete: lineage.complete,
            context: ContextReport {
                unit: ctx.unit.as_ref().map(|u| Cow::Borrowed(&*u.name)),
                container: ctx.container.as_ref().map(|c| ContainerReport {
                    runtime: Cow::Borrowed(c.runtime.as_str()),
                    id: Cow::Borrowed(&*c.id),
                }),
                tmux: ctx.tmux.as_ref().map(|t| Cow::Borrowed(&*t.pane)),
                cgroup: ctx.cgroup.as_ref().map(|c| Cow::Borrowed(&*c.path)),
            },
            origin: lineage.origin.as_ref().map(|o| OriginReport {
                kind: Cow::Borrowed(kind_id(o.kind)),
                package: o.package.as_deref().map(Cow::Borrowed),
                version: o.version.as_deref().map(Cow::Borrowed),
                phase: o.phase.as_deref().map(Cow::Borrowed),
                confidence: Cow::Borrowed(confidence_id(o.confidence)),
                via_pid: o.via.pid,
                evidence: o.evidence.iter().map(|e| Cow::Borrowed(&**e)).collect(),
            }),
            lineage: lineage.id,
        }
    }

    /// What a [`Filter`](crate::filter::Filter) needs to know about this change.
    pub fn candidate(&self) -> Candidate<'_> {
        Candidate {
            paths: [
                Some(Path::new(&*self.path)),
                self.old_path.as_deref().map(Path::new),
                self.target.as_deref().map(Path::new),
            ],
            comm: &self.comm,
            uid: self.uid,
            tgid: self.proc.pid,
            unit: self.context.unit.as_deref(),
        }
    }

    /// The acting process, then its ancestors.
    pub fn chain(&self) -> impl Iterator<Item = &ProcReport<'a>> {
        std::iter::once(&self.proc).chain(&self.ancestry)
    }
}

/// Encoded lineages a [`LineEncoder`] keeps, by [`LineageId`].
const LINEAGE_SLOTS: usize = 64;

/// Encodes lines as NDJSON, newline included. The fields from `proc` to `origin`, most of a
/// touch line, are encoded once per [`LineageId`] and reused while kept: changes come in runs
/// by one process. The bytes are those of `serde_json` on the [`Line`].
#[derive(Debug)]
pub struct LineEncoder {
    /// The line being encoded, reused.
    line: Vec<u8>,
    /// Encoded lineage fields as a JSON object, `{"proc":…}`, in slot `id % LINEAGE_SLOTS`.
    lineages: Vec<Option<(LineageId, Vec<u8>)>>,
}

impl Default for LineEncoder {
    fn default() -> Self {
        Self {
            line: Vec::new(),
            lineages: vec![None; LINEAGE_SLOTS],
        }
    }
}

impl LineEncoder {
    /// `line` as one line of JSON.
    pub fn encode(&mut self, line: &Line<'_>) -> serde_json::Result<&[u8]> {
        self.line.clear();
        match line {
            Line::Touch(change) => match change.lineage {
                Some(id) => self.touch(change, id)?,
                None => serde_json::to_writer(&mut self.line, line)?,
            },
            _ => serde_json::to_writer(&mut self.line, line)?,
        }
        self.line.push(b'\n');
        Ok(&self.line)
    }

    /// Splices the object of the head fields and the (kept) object of the lineage fields.
    fn touch(&mut self, change: &ChangeReport<'_>, id: LineageId) -> serde_json::Result<()> {
        serde_json::to_writer(&mut self.line, &TouchHead::of(change))?;
        // Both objects have fields: `{"type":…,"ns_pid":7}` + `{"proc":…}` is one object
        // once the head's `}` and the lineage's `{` become a `,`.
        self.line.pop();
        self.line.push(b',');
        let slot = &mut self.lineages[usize::try_from(id.0).unwrap_or(0) % LINEAGE_SLOTS];
        let lineage = match slot {
            Some((kept, encoded)) if *kept == id => encoded,
            _ => {
                let mut encoded = slot.take().map(|(_, bytes)| bytes).unwrap_or_default();
                encoded.clear();
                serde_json::to_writer(&mut encoded, &TouchLineage::of(change))?;
                &mut slot.insert((id, encoded)).1
            }
        };
        self.line.extend_from_slice(&lineage[1..]);
        Ok(())
    }
}

/// The fields of a touch line before its lineage, `type` first: as [`Line`] writes them.
#[derive(Serialize)]
#[serde(tag = "type", rename = "touch")]
struct TouchHead<'r> {
    v: Version,
    ts: Timestamp,
    #[serde(with = "op_name")]
    op: Op,
    path: &'r str,
    old_path: Option<&'r str>,
    target: Option<&'r str>,
    truncated: bool,
    bytes: Option<u64>,
    calls: Option<u64>,
    file: FileReport,
    change: Option<ChangeDetail>,
    tid: u32,
    comm: &'r str,
    uid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ns_pid: Option<u32>,
}

impl<'r> TouchHead<'r> {
    fn of(change: &'r ChangeReport<'_>) -> Self {
        Self {
            v: change.v,
            ts: change.ts,
            op: change.op,
            path: &change.path,
            old_path: change.old_path.as_deref(),
            target: change.target.as_deref(),
            truncated: change.truncated,
            bytes: change.bytes,
            calls: change.calls,
            file: change.file,
            change: change.change,
            tid: change.tid,
            comm: &change.comm,
            uid: change.uid,
            ns_pid: change.ns_pid,
        }
    }
}

/// The lineage fields of a touch line, `proc` to `origin`.
#[derive(Serialize)]
struct TouchLineage<'r, 'a> {
    proc: &'r ProcReport<'a>,
    ancestry: &'r [ProcReport<'a>],
    ancestry_complete: bool,
    context: &'r ContextReport<'a>,
    origin: Option<&'r OriginReport<'a>>,
}

impl<'r, 'a> TouchLineage<'r, 'a> {
    fn of(change: &'r ChangeReport<'a>) -> Self {
        Self {
            proc: &change.proc,
            ancestry: &change.ancestry,
            ancestry_complete: change.ancestry_complete,
            context: &change.context,
            origin: change.origin.as_ref(),
        }
    }
}

/// File identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReport {
    /// Device of the filesystem.
    pub dev: Dev,
    /// Inode number; 0 for a name being created.
    pub ino: u64,
    /// `i_mode`, or the requested mode for creations.
    pub mode: FileMode,
}

/// What an operation changed; only the fields of its kind are present.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeDetail {
    /// New permissions (`chmod`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Perms>,
    /// Permissions before a `chmod`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_mode: Option<Perms>,
    /// New owner (`chown`), if changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// New group (`chown`), if changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// New size (`truncate`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Device number of a new special file (`mknod`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdev: Option<Dev>,
    /// `RENAME_EXCHANGE`: the two names swapped files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange: Option<bool>,
    /// `RENAME_NOREPLACE` was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noreplace: Option<bool>,
    /// A rename replaced an existing file at the new name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced: Option<bool>,
    /// A shared mapping of the file became writable, by this system call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped: Option<MapVia>,
}

impl ChangeDetail {
    /// The detail of `touch`; `None` when there is nothing beyond its op (or, for writes,
    /// its byte counts).
    fn of(touch: &Touch) -> Option<Self> {
        let mut c = Self::default();
        match touch.change {
            Change::None | Change::Write { .. } => return None,
            Change::Mode(mode) => {
                c.mode = Some(Perms(mode));
                c.old_mode = Some(Perms(touch.mode));
            }
            Change::Owner { uid, gid } => {
                c.uid = uid;
                c.gid = gid;
            }
            Change::Size(size) => c.size = Some(size),
            Change::Rename { flags, replaced } => {
                c.exchange = Some(flags & RENAME_EXCHANGE != 0);
                c.noreplace = Some(flags & RENAME_NOREPLACE != 0);
                c.replaced = Some(replaced);
            }
            Change::Node(rdev) => c.rdev = Some(Dev(rdev)),
            Change::Mapped { via } => c.mapped = Some(via),
        }
        Some(c)
    }
}

/// One process of a change's lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcReport<'a> {
    /// Process id.
    pub pid: u32,
    /// Process name.
    pub comm: Cow<'a, str>,
    /// Executable.
    pub exe: Option<Cow<'a, str>>,
    /// Arguments, the program name first.
    pub argv: Vec<Cow<'a, str>>,
    /// `argv` was cut at the kernel's capture limit.
    pub argv_truncated: bool,
    /// Working directory.
    pub cwd: Option<Cow<'a, str>>,
    /// Real uid.
    pub uid: Option<u32>,
    /// Whether the process had exited by the time the change was reported; `null` when
    /// fsblame did not track the process (then only `pid`, `comm` and `uid` are known).
    pub exited: Option<bool>,
    /// When it exited, if known.
    pub exit_ts: Option<Timestamp>,
}

impl<'a> ProcReport<'a> {
    /// A tracked process.
    fn new(info: &'a ProcInfo, clock: Clock) -> Self {
        Self {
            pid: info.key.pid,
            comm: Cow::Borrowed(&*info.comm),
            exe: info.exe.as_deref().map(Path::to_string_lossy),
            argv: info.argv.iter().map(|a| a.to_string_lossy()).collect(),
            argv_truncated: info.argv_truncated,
            cwd: info.cwd.as_deref().map(Path::to_string_lossy),
            uid: info.uid,
            exited: Some(info.exit.is_some()),
            exit_ts: info
                .exit
                .filter(|exit| exit.ts_ns > 0)
                .map(|exit| Timestamp::from_boot(clock, exit.ts_ns)),
        }
    }

    /// An actor fsblame has no record of.
    fn untracked(actor: &'a Actor) -> Self {
        Self {
            pid: actor.tgid,
            comm: Cow::Borrowed(actor.comm.as_str()),
            exe: None,
            argv: Vec::new(),
            argv_truncated: false,
            cwd: None,
            uid: Some(actor.uid),
            exited: None,
            exit_ts: None,
        }
    }

    /// Whether fsblame tracked the process.
    pub fn tracked(&self) -> bool {
        self.exited.is_some()
    }
}

/// Where the actor runs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextReport<'a> {
    /// systemd unit.
    pub unit: Option<Cow<'a, str>>,
    /// Container.
    pub container: Option<ContainerReport<'a>>,
    /// tmux pane, such as `%3`.
    pub tmux: Option<Cow<'a, str>>,
    /// cgroup v2 path.
    pub cgroup: Option<Cow<'a, str>>,
}

/// A container, written `RUNTIME:ID`, such as `docker:3f4e…`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerReport<'a> {
    /// Runtime name, such as `docker` or `podman`.
    pub runtime: Cow<'a, str>,
    /// Full container id, or the machine name for LXC and nspawn.
    pub id: Cow<'a, str>,
}

impl ContainerReport<'_> {
    /// The first 12 characters of the id, as `docker ps` shows it.
    pub fn short_id(&self) -> &str {
        match self.id.char_indices().nth(12) {
            Some((end, _)) => &self.id[..end],
            None => &self.id,
        }
    }
}

impl Serialize for ContainerReport<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{}:{}", self.runtime, self.id))
    }
}

impl<'de> Deserialize<'de> for ContainerReport<'_> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        parse_str(deserializer, "a RUNTIME:ID container", |text| {
            let (runtime, id) = text.split_once(':')?;
            Some(Self {
                runtime: Cow::Owned(runtime.to_owned()),
                id: Cow::Owned(id.to_owned()),
            })
        })
    }
}

/// The build step behind a change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginReport<'a> {
    /// `npm-lifecycle`, `pnpm-lifecycle`, `yarn-lifecycle`, `bun-lifecycle`,
    /// `cargo-build-script`, `pip-build`, `make`, or `other`.
    pub kind: Cow<'a, str>,
    /// Package being built.
    pub package: Option<Cow<'a, str>>,
    /// Its version.
    pub version: Option<Cow<'a, str>>,
    /// Lifecycle phase, such as `postinstall`.
    pub phase: Option<Cow<'a, str>>,
    /// `high`, `medium`, `low` or `unknown`.
    pub confidence: Cow<'a, str>,
    /// The process whose environment identified the step.
    pub via_pid: u32,
    /// The facts the classification rests on.
    pub evidence: Vec<Cow<'a, str>>,
}

fn kind_id(kind: OriginKind) -> &'static str {
    match kind {
        OriginKind::NpmLifecycle => "npm-lifecycle",
        OriginKind::PnpmLifecycle => "pnpm-lifecycle",
        OriginKind::YarnLifecycle => "yarn-lifecycle",
        OriginKind::BunLifecycle => "bun-lifecycle",
        OriginKind::CargoBuildScript => "cargo-build-script",
        OriginKind::PipBuild => "pip-build",
        OriginKind::Make => "make",
        _ => "other",
    }
}

fn confidence_id(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
        _ => "unknown",
    }
}

/// Why kernel-side information was lost. Later revisions of schema version 1 may add
/// reasons; a reason this version does not know reads as [`LossReason::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LossReason {
    /// Records were dropped because the ring buffer was full: changes or process events
    /// (lineage) are missing.
    RingFull,
    /// The kernel's write table evicted bindings: the byte and call counts of their latest
    /// writes are missing.
    WriteEvicted,
    /// The kernel's tracked-process table was full (`fsblame run`, `watch --tree`): new
    /// processes of tracked ones were left untracked, and their changes are missing.
    TrackFull,
    /// Records of the changes made before the stop were still in the ring buffer when
    /// fsblame stopped reading it (a backlog it could not read in time, or another stop
    /// signal): changes or process events are missing.
    Unread,
    /// A reason a later fsblame wrote that this one does not know; what `count` counts is
    /// unknown too. Never produced live; written back as `other`.
    #[serde(other)]
    Other,
}

/// Losses since the previous `lost` line of the same reason: `{"type":"lost",...}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LostReport {
    /// Schema version.
    pub v: Version,
    /// When the loss was noticed.
    pub ts: Timestamp,
    /// What was lost.
    pub reason: LossReason,
    /// Records ([`LossReason::RingFull`], [`LossReason::Unread`]), write bindings
    /// ([`LossReason::WriteEvicted`]), processes ([`LossReason::TrackFull`]), or units
    /// this version does not know ([`LossReason::Other`]).
    pub count: u64,
}

/// Losses of a whole run. Totals of reasons this version does not know are ignored on read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossTotals {
    /// Records dropped because the ring buffer was full.
    pub ring_full: u64,
    /// Write bindings evicted before their latest counts were read.
    pub write_evicted: u64,
    /// Processes left untracked because the tracked-process table was full.
    #[serde(default)]
    pub track_full: u64,
    /// Records left in the ring buffer when fsblame stopped reading it.
    #[serde(default)]
    pub unread: u64,
}

impl LossTotals {
    /// Whether nothing was lost.
    pub fn is_empty(&self) -> bool {
        self.ring_full == 0 && self.write_evicted == 0 && self.track_full == 0 && self.unread == 0
    }
}

/// What a run reported: `{"type":"summary",...}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryReport<'a> {
    /// Schema version.
    pub v: Version,
    /// When the run stopped.
    pub ts: Timestamp,
    /// Changes reported.
    pub changes: u64,
    /// What the kernel side lost.
    pub lost: LossTotals,
    /// Changes by group, most changes first; [`Group::Other`] last.
    pub groups: Vec<GroupReport<'a>>,
}

/// The changes of one group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupReport<'a> {
    /// What the changes have in common.
    pub group: Group<'a>,
    /// Changes.
    pub changes: u64,
    /// Changes per op, such as `{"write":3,"create":1}`.
    pub ops: OpCounts,
    /// Distinct paths changed (counted up to a cap).
    pub paths: u64,
    /// Changes to paths beyond the cap, whose distinctness was not tracked; usually 0.
    pub paths_untracked: u64,
    /// The first few distinct paths, in the order they changed.
    pub first_paths: Vec<Cow<'a, str>>,
}

/// What groups changes in a summary: the build step when there is one, else the command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group<'a> {
    /// A build step: `{"origin":{...}}`.
    Origin(OriginKey<'a>),
    /// The acting process's `comm`: `{"comm":"vim"}`.
    Comm(Cow<'a, str>),
    /// Every group beyond the cap: `"other"`.
    Other,
}

/// A build step, as summaries group by it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginKey<'a> {
    /// As [`OriginReport::kind`].
    pub kind: Cow<'a, str>,
    /// Package being built.
    pub package: Option<Cow<'a, str>>,
    /// Its version.
    pub version: Option<Cow<'a, str>>,
    /// Lifecycle phase.
    pub phase: Option<Cow<'a, str>>,
}

impl OriginKey<'_> {
    /// This key with each text converted by `text`.
    fn convert<'s, 'b>(&'s self, text: impl Fn(&'s str) -> Cow<'b, str>) -> OriginKey<'b> {
        OriginKey {
            kind: text(&self.kind),
            package: self.package.as_deref().map(&text),
            version: self.version.as_deref().map(&text),
            phase: self.phase.as_deref().map(&text),
        }
    }
}

impl<'a> Group<'a> {
    /// The group of `change`.
    fn of(change: &'a ChangeReport<'_>) -> Self {
        match &change.origin {
            Some(o) => Self::Origin(OriginKey {
                kind: Cow::Borrowed(&o.kind),
                package: o.package.as_deref().map(Cow::Borrowed),
                version: o.version.as_deref().map(Cow::Borrowed),
                phase: o.phase.as_deref().map(Cow::Borrowed),
            }),
            None => Self::Comm(Cow::Borrowed(&change.proc.comm)),
        }
    }

    /// A copy borrowing from `self`.
    fn reborrow(&self) -> Group<'_> {
        match self {
            Self::Origin(k) => Group::Origin(k.convert(Cow::Borrowed)),
            Self::Comm(comm) => Group::Comm(Cow::Borrowed(comm)),
            Self::Other => Group::Other,
        }
    }

    /// An owned copy.
    fn to_owned_group(&self) -> Group<'static> {
        let owned = |text: &str| Cow::Owned(text.to_owned());
        match self {
            Self::Origin(k) => Group::Origin(k.convert(owned)),
            Self::Comm(comm) => Group::Comm(owned(comm)),
            Self::Other => Group::Other,
        }
    }
}

/// A count per [`Op`], written as an object of the non-zero counts in [`Op::ALL`] order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpCounts([u64; Op::ALL.len()]);

impl OpCounts {
    /// The count of `op`.
    pub fn get(&self, op: Op) -> u64 {
        self.0[op_index(op)]
    }

    /// Counts one more `op`.
    pub fn add(&mut self, op: Op) {
        self.0[op_index(op)] += 1;
    }

    /// The ops counted at least once, with their counts, in [`Op::ALL`] order.
    pub fn iter(&self) -> impl Iterator<Item = (Op, u64)> {
        Op::ALL
            .into_iter()
            .zip(self.0)
            .filter(|&(_, count)| count > 0)
    }
}

impl Serialize for OpCounts {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.iter().map(|(op, count)| (op.name(), count)))
    }
}

impl<'de> Deserialize<'de> for OpCounts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut counts = Self::default();
        for (name, count) in BTreeMap::<Cow<'_, str>, u64>::deserialize(deserializer)? {
            let op = Op::ALL
                .into_iter()
                .find(|op| op.name() == name)
                .ok_or_else(|| D::Error::custom(format_args!("{name:?} is not an operation")))?;
            counts.0[op_index(op)] = count;
        }
        Ok(counts)
    }
}

/// The tally of one [`Group`].
#[derive(Debug)]
struct Tally {
    group: Group<'static>,
    changes: u64,
    ops: OpCounts,
    /// Distinct paths, at most [`SUMMARY_PATHS`].
    seen: HashSet<Box<str>>,
    /// Changes to paths not in `seen` once it was full.
    paths_untracked: u64,
    /// The first [`SUMMARY_FIRST_PATHS`] distinct paths.
    first: Vec<Box<str>>,
}

impl Tally {
    fn new(group: Group<'static>) -> Self {
        Self {
            group,
            changes: 0,
            ops: OpCounts::default(),
            seen: HashSet::new(),
            paths_untracked: 0,
            first: Vec::new(),
        }
    }

    fn add(&mut self, change: &ChangeReport<'_>) {
        self.changes += 1;
        self.ops.add(change.op);
        let path = &*change.path;
        if self.seen.contains(path) {
            return;
        }
        if self.seen.len() < SUMMARY_PATHS {
            self.seen.insert(path.into());
            if self.first.len() < SUMMARY_FIRST_PATHS {
                self.first.push(path.into());
            }
        } else {
            self.paths_untracked += 1;
        }
    }

    fn report(&self) -> GroupReport<'_> {
        GroupReport {
            group: self.group.reborrow(),
            changes: self.changes,
            ops: self.ops,
            paths: self.seen.len() as u64,
            paths_untracked: self.paths_untracked,
            first_paths: self.first.iter().map(|p| Cow::Borrowed(&**p)).collect(),
        }
    }
}

/// Accumulates the changes of a run for its [`SummaryReport`], in bounded memory: at most
/// [`SUMMARY_GROUPS`] groups (then [`Group::Other`]) of at most [`SUMMARY_PATHS`] remembered
/// paths each.
#[derive(Debug, Default)]
pub struct Summary {
    groups: Vec<Tally>,
    other: Option<Tally>,
    changes: u64,
}

impl Summary {
    /// An empty summary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts `change`.
    pub fn add(&mut self, change: &ChangeReport<'_>) {
        self.changes += 1;
        let group = Group::of(change);
        if let Some(tally) = self.groups.iter_mut().find(|t| t.group == group) {
            tally.add(change);
        } else if self.groups.len() < SUMMARY_GROUPS {
            let mut tally = Tally::new(group.to_owned_group());
            tally.add(change);
            self.groups.push(tally);
        } else {
            self.other
                .get_or_insert_with(|| Tally::new(Group::Other))
                .add(change);
        }
    }

    /// The summary line, stamped `ts`, with the run's `lost` totals.
    pub fn report(&self, ts: Timestamp, lost: LossTotals) -> SummaryReport<'_> {
        let mut groups: Vec<GroupReport<'_>> = self.groups.iter().map(Tally::report).collect();
        // Stable: groups with equal counts stay in the order they first changed something.
        groups.sort_by_key(|g| std::cmp::Reverse(g.changes));
        groups.extend(self.other.as_ref().map(Tally::report));
        SummaryReport {
            v: Version,
            ts,
            changes: self.changes,
            lost,
            groups,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn text(s: &str) -> Cow<'static, str> {
        Cow::Owned(s.to_owned())
    }

    fn proc(pid: u32, comm: &str, argv: &[&str], exited: bool) -> ProcReport<'static> {
        ProcReport {
            pid,
            comm: text(comm),
            exe: Some(text(&format!("/usr/bin/{comm}"))),
            argv: argv.iter().map(|a| text(a)).collect(),
            argv_truncated: false,
            cwd: Some(text("/home/u/proj")),
            uid: Some(1000),
            exited: Some(exited),
            exit_ts: exited.then_some(Timestamp(1_791_986_532_250_000_000)),
        }
    }

    /// A chmod by a tracked process under an npm lifecycle step, with every context fact.
    pub(crate) fn chmod() -> ChangeReport<'static> {
        ChangeReport {
            v: Version,
            ts: Timestamp(1_791_986_531_123_456_000),
            op: Op::Chmod,
            path: text("/home/u/proj/run.sh"),
            old_path: None,
            target: None,
            truncated: false,
            bytes: None,
            calls: None,
            file: FileReport {
                dev: Dev(259 << 20 | 2),
                ino: 42,
                mode: FileMode(0o100_644),
            },
            change: Some(ChangeDetail {
                mode: Some(Perms(0o755)),
                old_mode: Some(Perms(0o644)),
                ..ChangeDetail::default()
            }),
            tid: 4243,
            comm: text("chmod"),
            uid: 1000,
            ns_pid: Some(7),
            proc: proc(4242, "chmod", &["chmod", "+x", "run.sh"], true),
            ancestry: vec![proc(
                4000,
                "node",
                &["node", "/usr/bin/npm", "install"],
                false,
            )],
            ancestry_complete: true,
            context: ContextReport {
                unit: Some(text("session-2.scope")),
                container: Some(ContainerReport {
                    runtime: text("docker"),
                    id: text("3f4e5d6c7b8a9f0e1d2c"),
                }),
                tmux: Some(text("%3")),
                cgroup: Some(text("/user.slice/session-2.scope")),
            },
            origin: Some(OriginReport {
                kind: text("npm-lifecycle"),
                package: Some(text("demo")),
                version: Some(text("1.0.0")),
                phase: Some(text("postinstall")),
                confidence: text("high"),
                via_pid: 4000,
                evidence: vec![text("npm_lifecycle_event=postinstall")],
            }),
            lineage: None,
        }
    }

    #[test]
    fn encoded_lines_are_serde_json_also_with_kept_lineages() {
        let id = LineageId::fresh();
        let tracked = ChangeReport {
            lineage: Some(id),
            ..chmod()
        };
        let renamed = ChangeReport {
            op: Op::Rename,
            old_path: Some(text("/home/u/proj/old.sh")),
            ns_pid: None,
            lineage: Some(id),
            ..chmod()
        };
        // Another lineage in the same slot.
        let other = ChangeReport {
            ancestry: Vec::new(),
            origin: None,
            lineage: Some(LineageId(id.0 + LINEAGE_SLOTS as u64)),
            ..chmod()
        };
        let lines = [
            Line::Touch(tracked.clone()),
            Line::Touch(renamed),
            Line::Touch(other),
            Line::Touch(tracked),
            Line::Touch(chmod()),
            Line::Lost(LostReport {
                v: Version,
                ts: Timestamp(1_791_986_531_000_000_000),
                reason: LossReason::RingFull,
                count: 12,
            }),
        ];
        let mut encoder = LineEncoder::default();
        for line in &lines {
            let mut json = serde_json::to_vec(line).unwrap();
            json.push(b'\n');
            assert_eq!(
                String::from_utf8_lossy(encoder.encode(line).unwrap()),
                String::from_utf8_lossy(&json)
            );
        }
    }

    #[test]
    fn every_line_round_trips_through_json() {
        let mut summary = Summary::new();
        summary.add(&chmod());
        let lines = [
            Line::Touch(chmod()),
            Line::Lost(LostReport {
                v: Version,
                ts: Timestamp(1_791_986_531_000_000_000),
                reason: LossReason::RingFull,
                count: 12,
            }),
            Line::Lost(LostReport {
                v: Version,
                ts: Timestamp(1_791_986_539_000_000_000),
                reason: LossReason::Unread,
                count: 4,
            }),
            Line::Summary(summary.report(
                Timestamp(1_791_986_540_000_000_000),
                LossTotals {
                    ring_full: 12,
                    write_evicted: 1,
                    track_full: 2,
                    unread: 4,
                },
            )),
        ];
        for line in lines {
            let json = serde_json::to_string(&line).unwrap();
            assert_eq!(Line::parse(&json).unwrap(), line, "{json}");
        }
    }

    #[test]
    fn touch_lines_keep_the_documented_shape() {
        let json: serde_json::Value = serde_json::to_value(Line::Touch(chmod())).unwrap();
        assert_eq!(json["type"], "touch");
        assert_eq!(json["v"], VERSION);
        assert_eq!(json["ts"], "2026-10-14T14:02:11.123456Z");
        assert_eq!(json["op"], "chmod");
        assert_eq!(json["file"]["dev"], "259:2");
        assert_eq!(json["file"]["mode"], "100644");
        assert_eq!(
            json["change"],
            serde_json::json!({"mode": "0755", "old_mode": "0644"})
        );
        assert_eq!(json["bytes"], serde_json::Value::Null);
        assert_eq!(json["ns_pid"], 7);
        assert_eq!(json["context"]["container"], "docker:3f4e5d6c7b8a9f0e1d2c");
        assert_eq!(json["proc"]["exit_ts"], "2026-10-14T14:02:12.250000Z");
    }

    #[test]
    fn other_versions_and_unknown_ops_are_rejected() {
        let json = serde_json::to_string(&Line::Touch(chmod())).unwrap();
        let v2 = json.replacen("\"v\":1", "\"v\":2", 1);
        let error = Line::parse(&v2).unwrap_err().to_string();
        assert!(error.contains("report version 2"), "{error}");
        assert!(Line::parse(&json.replacen("\"chmod\"", "\"chmode\"", 1)).is_err());
        // Fields a later minor revision adds are ignored.
        let extra = json.replacen("\"v\":1", "\"v\":1,\"later\":true", 1);
        assert!(Line::parse(&extra).is_ok());
    }

    #[test]
    fn loss_reasons_of_a_later_revision_still_parse() {
        let line = Line::parse(
            r#"{"type":"lost","v":1,"ts":"2026-10-14T14:02:11Z","reason":"cache-full","count":5}"#,
        )
        .unwrap();
        let Line::Lost(lost) = line else {
            panic!("not lost: {line:?}");
        };
        assert_eq!(lost.reason, LossReason::Other);
        assert_eq!(lost.count, 5);
        // Known reasons keep their names.
        let json = serde_json::to_value(LossReason::WriteEvicted).unwrap();
        assert_eq!(json, "write-evicted");
        // Replayed, an unknown one is written back as `other`.
        let json = serde_json::to_value(LossReason::Other).unwrap();
        assert_eq!(json, "other");

        let summary = Line::parse(
            r#"{"type":"summary","v":1,"ts":"2026-10-14T14:02:11Z","changes":0,
                "lost":{"ring_full":2,"write_evicted":0,"cache_full":7},"groups":[]}"#,
        )
        .unwrap();
        let Line::Summary(summary) = summary else {
            panic!("not a summary: {summary:?}");
        };
        assert_eq!(
            summary.lost,
            LossTotals {
                ring_full: 2,
                ..LossTotals::default()
            }
        );
    }

    #[test]
    fn summary_groups_by_origin_else_comm_and_bounds_paths() {
        let mut summary = Summary::new();
        let mut vim = chmod();
        vim.origin = None;
        vim.op = Op::Write;
        vim.proc.comm = text("vim");
        for i in 0..SUMMARY_PATHS + 5 {
            vim.path = Cow::Owned(format!("/p/{i}"));
            summary.add(&vim);
            summary.add(&vim);
        }
        summary.add(&chmod());
        let report = summary.report(Timestamp(0), LossTotals::default());
        assert_eq!(report.changes, 2 * (SUMMARY_PATHS as u64 + 5) + 1);
        let [first, second] = &report.groups[..] else {
            panic!("two groups: {:?}", report.groups);
        };
        assert_eq!(first.group, Group::Comm(text("vim")));
        assert_eq!(first.ops.get(Op::Write), 2 * (SUMMARY_PATHS as u64 + 5));
        assert_eq!(first.paths, SUMMARY_PATHS as u64);
        assert_eq!(first.paths_untracked, 10);
        assert_eq!(
            first.first_paths,
            [text("/p/0"), text("/p/1"), text("/p/2")]
        );
        assert!(matches!(&second.group, Group::Origin(k) if k.package.as_deref() == Some("demo")));
    }

    #[test]
    fn summary_folds_groups_beyond_the_cap_into_other() {
        let mut summary = Summary::new();
        let mut change = chmod();
        change.origin = None;
        for i in 0..=SUMMARY_GROUPS {
            change.proc.comm = Cow::Owned(format!("c{i}"));
            summary.add(&change);
        }
        let report = summary.report(Timestamp(0), LossTotals::default());
        assert_eq!(report.groups.len(), SUMMARY_GROUPS + 1);
        assert_eq!(report.groups.last().unwrap().group, Group::Other);
    }
}
