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

/// What an optional program contributes to the ops it serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Reports its ops: without it they are not reported.
    Reports,
    /// Reports changes of its ops the reporting program does not see (writes through shared
    /// mappings), or commits the ones it held (an `open(O_CREAT)` that created the file); the
    /// text says what is lost without it.
    Adds(&'static str),
    /// Adds detail to what another program reports (byte counts, the open instance of a
    /// struct file, the cwd): without it no change is lost, only that detail, which the text
    /// says.
    Supplements(&'static str),
    /// An fexit on the VFS function that runs the check of its ops: with it attached, the
    /// check holds the record and the fexit reports it only if the function succeeded; without
    /// it the check reports the op at once, whatever becomes of it.
    Confirms {
        /// What is lost without it.
        lost: &'static str,
        /// The `.rodata` [`ExitShape`](abi::ExitShape) the loader sets from the function's
        /// prototype in the running kernel's BTF; `None` for a prototype that is the same on
        /// every supported kernel.
        shape: Option<&'static str>,
    },
}

impl Role {
    /// What is lost without the program; `None` for one that reports its ops.
    pub const fn lost(self) -> Option<&'static str> {
        match self {
            Self::Reports => None,
            Self::Adds(lost) | Self::Supplements(lost) | Self::Confirms { lost, .. } => Some(lost),
        }
    }

    /// Whether a run of the program the kernel skips can lose or misreport a change: every
    /// role but [`Supplements`](Self::Supplements), whose skipped run only loses detail.
    pub const fn skip_loses_changes(self) -> bool {
        !matches!(self, Self::Supplements(_))
    }
}

/// An optional program of the tracer and its attach point.
#[derive(Clone, Copy, Debug)]
pub struct Hook {
    /// Program name in `fsblame.bpf.c`.
    pub program: &'static str,
    /// Kernel function of an fentry or fexit program; the tracepoint of [`EXEC_CWD_HOOK`].
    pub function: &'static str,
    /// Ops the program serves.
    pub ops: &'static [Op],
    /// Needed whatever ops are selected (scope-cache invalidation, cwd capture).
    pub always: bool,
    /// What the program contributes.
    pub role: Role,
}

impl Hook {
    /// Whether the hook must be attached for `ops`.
    pub fn wanted(&self, ops: OpSet) -> bool {
        self.always || self.ops.iter().any(|&op| ops.contains(op))
    }

    /// The `.rodata` shape the loader sets for the program (see [`Role::Confirms`]).
    pub const fn shape(&self) -> Option<&'static str> {
        match self.role {
            Role::Confirms { shape, .. } => shape,
            Role::Reports | Role::Adds(_) | Role::Supplements(_) => None,
        }
    }
}

/// The fentry and fexit hooks, in attach order.
pub const FS_HOOKS: [Hook; 24] = [
    Hook {
        program: "on_rw_verify_area",
        function: "rw_verify_area",
        ops: &[Op::Write],
        always: false,
        role: Role::Supplements("writes are reported without byte counts"),
    },
    Hook {
        program: "on_file_free",
        function: "security_file_free",
        ops: &[Op::Write],
        always: false,
        role: Role::Supplements(
            "writes to one file through successive opens may be reported as one window when \
             the kernel reuses the struct file",
        ),
    },
    Hook {
        program: "on_file_permission",
        function: "security_file_permission",
        ops: &[Op::Write],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_mmap_file",
        function: "security_mmap_file",
        ops: &[Op::Write],
        always: false,
        role: Role::Adds("writes through shared mmap(2) mappings are not reported"),
    },
    Hook {
        program: "on_file_mprotect",
        function: "security_file_mprotect",
        ops: &[Op::Write],
        always: false,
        role: Role::Adds(
            "writes through shared mappings made writable by mprotect(2) are not reported",
        ),
    },
    Hook {
        program: "on_create",
        function: "security_inode_create",
        ops: &[Op::Create],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_file_post_open",
        function: "security_file_post_open",
        ops: &[Op::Create],
        always: false,
        role: Role::Adds(
            "an open(O_CREAT) of an existing file not yet in the dentry cache, or a create that \
             fails, is reported as a create",
        ),
    },
    Hook {
        program: "on_vfs_create",
        function: "vfs_create",
        ops: &[Op::Create],
        always: false,
        role: Role::Confirms {
            lost: "creates that fail may be reported",
            shape: Some("shape_vfs_create"),
        },
    },
    Hook {
        program: "on_mkdir",
        function: "security_inode_mkdir",
        ops: &[Op::Mkdir],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_vfs_mkdir",
        function: "vfs_mkdir",
        ops: &[Op::Mkdir],
        always: false,
        role: Role::Confirms {
            lost: "mkdirs that fail may be reported",
            shape: Some("shape_vfs_mkdir"),
        },
    },
    Hook {
        program: "on_mknod",
        function: "security_inode_mknod",
        ops: &[Op::Mknod],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_vfs_mknod",
        function: "vfs_mknod",
        ops: &[Op::Mknod],
        always: false,
        role: Role::Confirms {
            lost: "mknods that fail may be reported",
            shape: Some("shape_vfs_mknod"),
        },
    },
    Hook {
        program: "on_symlink",
        function: "security_inode_symlink",
        ops: &[Op::Symlink],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_vfs_symlink",
        function: "vfs_symlink",
        ops: &[Op::Symlink],
        always: false,
        role: Role::Confirms {
            lost: "symlinks that fail may be reported",
            shape: Some("shape_vfs_symlink"),
        },
    },
    Hook {
        program: "on_link",
        function: "security_inode_link",
        ops: &[Op::Link],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_vfs_link",
        function: "vfs_link",
        ops: &[Op::Link],
        always: false,
        role: Role::Confirms {
            lost: "hard links that fail may be reported",
            shape: Some("shape_vfs_link"),
        },
    },
    Hook {
        program: "on_unlink",
        function: "security_inode_unlink",
        ops: &[Op::Unlink],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_vfs_unlink",
        function: "vfs_unlink",
        ops: &[Op::Unlink],
        always: false,
        role: Role::Confirms {
            lost: "unlinks that fail may be reported",
            shape: Some("shape_vfs_unlink"),
        },
    },
    Hook {
        program: "on_rmdir",
        function: "security_inode_rmdir",
        ops: &[Op::Rmdir],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_vfs_rmdir",
        function: "vfs_rmdir",
        ops: &[Op::Rmdir],
        always: false,
        role: Role::Confirms {
            lost: "rmdirs that fail, such as of a directory that is not empty, may be reported",
            shape: Some("shape_vfs_rmdir"),
        },
    },
    Hook {
        program: "on_rename",
        function: "security_inode_rename",
        ops: &[Op::Rename],
        always: true,
        role: Role::Reports,
    },
    Hook {
        program: "on_vfs_rename",
        function: "vfs_rename",
        ops: &[Op::Rename],
        always: true,
        role: Role::Confirms {
            lost: "a change below a directory being renamed may be judged by where the directory \
                   was until the next directory rename, and renames that fail may be reported",
            shape: None,
        },
    },
    Hook {
        program: "on_setattr",
        function: "security_inode_setattr",
        ops: &[Op::Chmod, Op::Chown, Op::Truncate, Op::Utimes, Op::Setattr],
        always: false,
        role: Role::Reports,
    },
    Hook {
        program: "on_notify_change",
        function: "notify_change",
        ops: &[Op::Chmod, Op::Chown, Op::Truncate, Op::Utimes, Op::Setattr],
        always: false,
        role: Role::Confirms {
            lost: "attribute changes that fail, such as a chmod by another user, may be reported",
            shape: Some("shape_notify_change"),
        },
    },
];

/// The `tp_btf` programs of the tracer and their tracepoints; all are required.
pub const SCHED_HOOKS: [(&str, &str); 3] = [
    ("on_fork", "sched_process_fork"),
    ("on_exec", "sched_process_exec"),
    ("on_exit", "sched_process_exit"),
];

/// The optional `tp_btf` program that captures the cwd of each exec for `on_exec`. Programs on
/// one tracepoint run in attach order, so it is attached before the [`SCHED_HOOKS`].
pub const EXEC_CWD_HOOK: Hook = Hook {
    program: "on_exec_cwd",
    function: "sched_process_exec",
    ops: &[],
    always: true,
    role: Role::Supplements("cwds are read from /proc, too late for processes that exit quickly"),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_runs_count_for_every_hook_that_can_lose_a_change_and_no_other() {
        let uncounted: Vec<&str> = FS_HOOKS
            .iter()
            .chain([&EXEC_CWD_HOOK])
            .filter(|hook| !hook.role.skip_loses_changes())
            .map(|hook| hook.program)
            .collect();
        // Byte counts, the open instance of a struct file, the cwd: detail, never a change.
        assert_eq!(
            uncounted,
            ["on_rw_verify_area", "on_file_free", "on_exec_cwd"]
        );
        // Programs that report, add or commit changes all count.
        for program in [
            "on_file_permission",
            "on_mmap_file",
            "on_file_mprotect",
            "on_file_post_open",
            "on_vfs_rename",
        ] {
            let hook = FS_HOOKS.iter().find(|h| h.program == program).unwrap();
            assert!(hook.role.skip_loses_changes(), "{program}");
        }
    }
}
