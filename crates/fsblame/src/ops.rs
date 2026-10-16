//! Reported operations and the kernel attach points behind them.

use clap::ValueEnum;
use fsblame_abi as abi;

/// A modifying file operation, as selected with `--op` and reported in output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ValueEnum)]
pub enum Op {
    /// Data written to a regular file.
    Write,
    /// Regular file created.
    Create,
    /// Directory created.
    Mkdir,
    /// Special file created.
    Mknod,
    /// Symbolic link created.
    Symlink,
    /// Hard link created.
    Link,
    /// Name removed.
    Unlink,
    /// Directory removed.
    Rmdir,
    /// Name moved.
    Rename,
    /// Mode changed.
    Chmod,
    /// Owner or group changed.
    Chown,
    /// Size changed.
    Truncate,
    /// Timestamps set.
    Utimes,
    /// Other attribute change.
    Setattr,
}

impl Op {
    /// Every op, in display order.
    pub const ALL: [Self; 14] = [
        Self::Write,
        Self::Create,
        Self::Mkdir,
        Self::Mknod,
        Self::Symlink,
        Self::Link,
        Self::Unlink,
        Self::Rmdir,
        Self::Rename,
        Self::Chmod,
        Self::Chown,
        Self::Truncate,
        Self::Utimes,
        Self::Setattr,
    ];

    /// The wire `OP_*` code.
    pub const fn code(self) -> u16 {
        match self {
            Self::Write => abi::OP_WRITE,
            Self::Create => abi::OP_CREATE,
            Self::Mkdir => abi::OP_MKDIR,
            Self::Mknod => abi::OP_MKNOD,
            Self::Symlink => abi::OP_SYMLINK,
            Self::Link => abi::OP_LINK,
            Self::Unlink => abi::OP_UNLINK,
            Self::Rmdir => abi::OP_RMDIR,
            Self::Rename => abi::OP_RENAME,
            Self::Chmod => abi::OP_CHMOD,
            Self::Chown => abi::OP_CHOWN,
            Self::Truncate => abi::OP_TRUNCATE,
            Self::Utimes => abi::OP_UTIMES,
            Self::Setattr => abi::OP_SETATTR,
        }
    }

    /// The op with wire code `code`.
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.code() == code)
    }

    /// Name in `--op` and JSON output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Create => "create",
            Self::Mkdir => "mkdir",
            Self::Mknod => "mknod",
            Self::Symlink => "symlink",
            Self::Link => "link",
            Self::Unlink => "unlink",
            Self::Rmdir => "rmdir",
            Self::Rename => "rename",
            Self::Chmod => "chmod",
            Self::Chown => "chown",
            Self::Truncate => "truncate",
            Self::Utimes => "utimes",
            Self::Setattr => "setattr",
        }
    }

    /// Past-tense verb for human output.
    pub const fn verb(self) -> &'static str {
        match self {
            Self::Write => "modified",
            Self::Create => "created",
            Self::Mkdir => "created dir",
            Self::Mknod => "created node",
            Self::Symlink => "symlinked",
            Self::Link => "hard-linked",
            Self::Unlink => "deleted",
            Self::Rmdir => "removed dir",
            Self::Rename => "renamed",
            Self::Chmod => "chmod",
            Self::Chown => "chown",
            Self::Truncate => "truncated",
            Self::Utimes => "touched",
            Self::Setattr => "attrs changed",
        }
    }
}

/// Set of ops as the BPF `op_mask`: bit `1 << OP_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpSet(u32);

impl OpSet {
    /// The ops in `ops`, or every op when `ops` is empty.
    pub fn new(ops: &[Op]) -> Self {
        let ops = if ops.is_empty() { &Op::ALL[..] } else { ops };
        Self(ops.iter().fold(0, |mask, op| mask | 1 << op.code()))
    }

    /// The BPF `op_mask` value.
    pub const fn mask(self) -> u32 {
        self.0
    }

    /// Whether `op` is selected.
    pub const fn contains(self, op: Op) -> bool {
        self.0 & (1 << op.code()) != 0
    }

    /// The selected ops, in display order.
    pub fn iter(self) -> impl Iterator<Item = Op> {
        Op::ALL.into_iter().filter(move |&op| self.contains(op))
    }
}

/// An fentry program of the tracer and the kernel function it attaches to.
#[derive(Clone, Copy, Debug)]
pub struct Hook {
    /// Program name in `fsblame.bpf.c`.
    pub program: &'static str,
    /// Kernel function.
    pub function: &'static str,
    /// Ops the program reports.
    pub ops: &'static [Op],
    /// Needed whatever ops are selected (scope-cache invalidation).
    pub always: bool,
    /// Produces records itself; `false` for hooks that only enrich another hook's records.
    pub reports: bool,
}

impl Hook {
    /// Whether the hook must be attached for `ops`.
    pub fn wanted(&self, ops: OpSet) -> bool {
        self.always || self.ops.iter().any(|&op| ops.contains(op))
    }
}

/// The fentry hooks, in attach order.
pub const FS_HOOKS: [Hook; 11] = [
    Hook {
        program: "on_rw_verify_area",
        function: "rw_verify_area",
        ops: &[Op::Write],
        always: false,
        reports: false,
    },
    Hook {
        program: "on_file_permission",
        function: "security_file_permission",
        ops: &[Op::Write],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_create",
        function: "security_inode_create",
        ops: &[Op::Create],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_mkdir",
        function: "security_inode_mkdir",
        ops: &[Op::Mkdir],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_mknod",
        function: "security_inode_mknod",
        ops: &[Op::Mknod],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_symlink",
        function: "security_inode_symlink",
        ops: &[Op::Symlink],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_link",
        function: "security_inode_link",
        ops: &[Op::Link],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_unlink",
        function: "security_inode_unlink",
        ops: &[Op::Unlink],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_rmdir",
        function: "security_inode_rmdir",
        ops: &[Op::Rmdir],
        always: false,
        reports: true,
    },
    Hook {
        program: "on_rename",
        function: "security_inode_rename",
        ops: &[Op::Rename],
        always: true,
        reports: true,
    },
    Hook {
        program: "on_setattr",
        function: "security_inode_setattr",
        ops: &[Op::Chmod, Op::Chown, Op::Truncate, Op::Utimes, Op::Setattr],
        always: false,
        reports: true,
    },
];

/// The `tp_btf` programs of the tracer and their tracepoints; all are required.
pub const SCHED_HOOKS: [(&str, &str); 3] = [
    ("on_fork", "sched_process_fork"),
    ("on_exec", "sched_process_exec"),
    ("on_exit", "sched_process_exit"),
];
