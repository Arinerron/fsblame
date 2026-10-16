// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * fsblame's tracer: reports modifying operations on watched paths with the acting process,
 * and streams fork/exec/exit so userspace can rebuild lineage (procctx).
 *
 * Scope: a dentry is in scope when it, or its nearest ancestor found in `roots`, is a watch
 * root (not an exclude). The verdict is cached per dentry in `verdicts`, validated against the
 * dentry's parent, inode number and `dir_epoch`, so an unwatched path costs one device check
 * and one LRU lookup. `dir_epoch` is bumped when a directory on a watched filesystem is about
 * to move (on_rename) and again once it has moved (on_renamed): a walk in between still sees
 * the old tree.
 *
 * Writes: rw_verify_area stashes the requested byte count per CPU; the security_file_permission
 * hook that follows consumes it and accumulates into `writes`, keyed by (tgid, struct file *).
 * Only the first write of a binding produces a record; userspace drains the totals. A shared
 * mapping that becomes writable (security_mmap_file, security_file_mprotect) is reported once
 * per binding (`mapped`): stores through it never pass a write hook. A binding belongs to one
 * open instance of its struct file (`files`); on_file_free ends the instance, so a reused
 * struct file starts a new binding.
 *
 * Creates: open(O_CREAT) of a name missing from the dentry cache runs the create check before
 * the lookup that tells whether the file exists. on_create leaves such a create (its dentry is
 * still in lookup) to on_file_post_open, which reports it if the open did create the file;
 * `creating` carries it from one to the other per thread.
 *
 * cwd: on_exec_cwd walks the new image's working directory into `cwd_buf` and on_exec, which
 * runs right after it on the same tracepoint and CPU, copies it into the exec record.
 *
 * Tracking (`track`, fsblame run and watch --tree): only the processes in `tracked` are
 * reported. The loader seeds it; on_fork adds the new processes of tracked ones and on_exit
 * removes a process once its last thread is gone. Every reporting path checks it after its
 * cheap scalar tests and before scope_of. With `scope` beyond the watch roots (fsblame run
 * without paths), every filesystem but the pseudo ones is in scope and paths are reported
 * relative to their filesystem root (ROOT_FSROOT), which userspace maps through mountinfo.
 * Both are .rodata: with tracking off and the default scope the checks compile away.
 *
 * Every fentry program that reports owns one `fs_buf` slot, so programs never share scratch
 * space: the same program cannot nest on one CPU (the kernel skips recursive runs).
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
/* vmlinux_min.h already declares the fixed-width types. */
#define __WIRE_TYPES
#include "fsblame_wire.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define MAY_WRITE 0x2
#define WRITE 1
#define S_IFMT 00170000
#define S_IFREG 0100000
#define S_IFDIR 0040000
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define ATTR_MODE (1U << 0)
#define ATTR_UID (1U << 1)
#define ATTR_GID (1U << 2)
#define ATTR_SIZE (1U << 3)
#define ATTR_ATIME (1U << 4)
#define ATTR_MTIME (1U << 5)
#define RENAME_EXCHANGE (1U << 1)
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_SHARED_VALIDATE 0x03
#define MAP_TYPE 0x0f
#define FMODE_WRITE 0x2
#define FMODE_CREATED (1U << 20)
#define VM_WRITE 0x2
#define VM_SHARED 0x8
#define MAX_PID_NS_LEVEL 32
#define SB_KERNMOUNT (1UL << 22)

/* Magic numbers (uapi/linux/magic.h and the filesystems' sources) of the filesystems that
 * expose kernel state rather than files: out of scope beyond the watch roots. */
#define PROC_SUPER_MAGIC 0x9fa0
#define SYSFS_MAGIC 0x62656572
#define CGROUP_SUPER_MAGIC 0x27e0eb
#define CGROUP2_SUPER_MAGIC 0x63677270
#define DEVPTS_SUPER_MAGIC 0x1cd1
#define DEBUGFS_MAGIC 0x64626720
#define TRACEFS_MAGIC 0x74726163
#define BPF_FS_MAGIC 0xcafe4a11
#define SECURITYFS_MAGIC 0x73636673
#define PSTOREFS_MAGIC 0x6165676c
#define CONFIGFS_MAGIC 0x62656570
#define BINFMTFS_MAGIC 0x42494e4d
#define MQUEUE_MAGIC 0x19800202
#define FUSE_CTL_SUPER_MAGIC 0x65735543
#define SELINUX_MAGIC 0xf97cff8c
#define SMACK_MAGIC 0x43415d53

/* fs_buf slots: the op programs use their op, the mapping and open programs the slots after
 * them. */
#define SLOT_MMAP OP_COUNT
#define SLOT_MPROTECT (OP_COUNT + 1)
#define SLOT_POST_OPEN (OP_COUNT + 2)
#define FS_SLOTS (OP_COUNT + 3)

/* d_parent hops of the scope walk. A record carries at most WALK_MAX names, but the walk has
 * to reach the root above a deeper change to tell whether it is watched: this covers any path
 * the kernel resolves in one call (PATH_MAX bytes hold at most 2048 names). bpf_loop's count
 * costs no verifier budget, and the verdict is walked once per dentry. */
#define SCOPE_WALK_MAX 4096

/* Payload offsets are masked or clamped to a constant before every write so the verifier can
 * bound them; the logical offsets never reach the mask (two paths of PATH_CAP + NAME_CAP, or
 * one exec record), so the masking never wraps. The slack after the mask covers the largest
 * single write. */
#define FS_DATA_MASK 4095
#define FS_DATA_BYTES (FS_DATA_MASK + 1 + PATH_CAP)
#define EXEC_DATA_MASK 16383
#define EXEC_DATA_BYTES (EXEC_DATA_MASK + 1 + ENV_CAP)
/* cwd names start below PATH_CAP and are at most NAME_CAP each. */
#define CWD_BYTES (PATH_CAP + NAME_CAP)
_Static_assert(ENV_CAP >= ARGV_CAP && ENV_CAP >= CWD_BYTES,
	       "the exec slack covers the largest of env, argv and cwd");
_Static_assert(FILENAME_CAP + ENV_CAP + ARGV_CAP + CWD_BYTES <= EXEC_DATA_MASK,
	       "exec offsets never wrap");

struct fs_scratch {
	struct fs_rec rec;
	u8 data[FS_DATA_BYTES];
	/* Write cursor of the path walk in `data`. It lives in the map value, not in the walk's
	 * stack context, because the verifier does not track map contents: every walk_step
	 * iteration then starts from the same state and bpf_loop converges after one pass.
	 * Tracked on the stack, each iteration's cursor range is a new state; two walks in one
	 * program (rename, link) multiplied past the 1M-instruction limit. */
	u32 cur;
	/* How the walk ended, here for the same reason: on the stack, each way the walk can stop
	 * is a state of its own that the rest of the program is verified from. */
	u32 cut; /* names left out: past the path's end, or past WALK_MAX */
	u32 top; /* got to the filesystem root */
	u32 _pad;
};

struct exec_scratch {
	struct exec_rec rec;
	u8 data[EXEC_DATA_BYTES];
};

/* The cwd on_exec_cwd walked for the exec in flight on this CPU, for on_exec. */
struct cwd_scratch {
	u64 bprm;  /* the exec's struct linux_binprm; 0 once on_exec consumed it */
	u32 tgid;  /* the exec's process */
	u32 flags; /* F_CWD (and F_CWD_TRUNC) once the walk is done */
	u32 cur;   /* write cursor in `data`, in the map value for the reason given at fs_scratch */
	u32 _pad;
	u8 data[CWD_BYTES];
};

/* Byte count of the write in flight on this CPU, from rw_verify_area. */
struct write_stash {
	u64 file;
	u64 count;
	u32 tid;
	u32 _pad;
};

/* A reported writable shared mapping of one (tgid, struct file); a mismatch means the struct
 * file or the pid was reused, so it is a new binding. */
struct mapping {
	u64 ino;
	u64 start_ns;
	u64 first_ns; /* when reported; stale if before the struct file's `since` */
	u32 dev;
	u32 _pad;
};

/*
 * One open instance of a struct file that has a binding. The slab hands a freed struct file
 * straight back, and ext4 hands a freed inode number back, so (tgid, file, ino) alone merges
 * the writes of distinct files. on_file_free drops the entry when the file is freed; without
 * that hook, a changed inode (address or i_generation) still tells instances apart. A binding
 * is the instance's when it started at or after `since`.
 */
struct file_seen {
	u64 since;
	u64 inode; /* struct inode * */
	u32 gen;   /* i_generation */
	u32 _pad;
};

/* Cached scope of one dentry; valid while parent, ino and epoch still match. */
struct verdict {
	u64 parent;
	u64 ino;
	u64 epoch;
	u32 root;  /* watch root id, or ROOT_NONE */
	u32 depth; /* names from the dentry up to, excluding, the root */
};

struct scope {
	u32 root;
	u32 depth;
};

/* .rodata, set by the loader before load; the verifier sees them as constants. */
const volatile u32 self_tgid = 0;
const volatile u32 op_mask = 0; /* bit (1 << OP_*) */
const volatile struct dev_filter dev_filter = {};
const volatile u32 scope = SCOPE_ROOTS; /* SCOPE_* */
const volatile u32 track = 0;           /* report only the processes in `tracked` */

/* Bumped on every directory rename on a watched filesystem: invalidates all verdicts. */
u64 dir_epoch = 0;

/* Set by the loader once every program is attached, so file events are reported from one
 * instant on for every op, not from whenever each hook happened to attach. Its own section
 * (map), so the loader writes it without touching dir_epoch. */
u32 armed SEC(".data.armed") = 0;

/* Set by on_file_post_open when it first runs: from then on it reports the creates that
 * on_create leaves to it. Written only here. */
u32 creates_confirmed = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); /* resized by the loader */
	__type(key, struct root_key);
	__type(value, struct root_val);
} roots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, u64); /* struct dentry * */
	__type(value, struct verdict);
} verdicts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct write_key);
	__type(value, struct write_val);
} writes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct write_key);
	__type(value, struct mapping);
} mapped SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u64); /* struct file * */
	__type(value, struct file_seen);
} files SEC(".maps");

/* The dentry, still in lookup, of each thread's open(O_CREAT) on a watched filesystem that
 * passed the create check before its lookup (see on_create). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);   /* tid */
	__type(value, u64); /* struct dentry * */
} creating SEC(".maps");

/* The processes whose changes are reported when `track` is set. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); /* resized by the loader when tracking */
	__type(key, u32);       /* tgid */
	__type(value, u8);
} tracked SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct write_stash);
} stash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FS_SLOTS); /* one slot per fentry program that reports */
	__type(key, u32);
	__type(value, struct fs_scratch);
} fs_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct exec_scratch);
} exec_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cwd_scratch);
} cwd_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_COUNT);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

static __always_inline u32 current_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline void count(u32 slot)
{
	u64 *n = bpf_map_lookup_elem(&stats, &slot);

	if (n)
		*n += 1;
}

static __always_inline void output(void *data, u64 size)
{
	if (bpf_ringbuf_output(&events, data, size, 0))
		count(STAT_RING_DROPS);
}

/* Whether the changes of process `tgid` are left out because tracking is on and it is not
 * tracked. */
static __always_inline bool untracked(u32 tgid)
{
	return track && !bpf_map_lookup_elem(&tracked, &tgid);
}

/* Whether the current process's `op` is reported: the op selected, the hooks armed, not
 * fsblame itself, and tracked when tracking. The map lookup goes last. */
static __always_inline bool reporting(u16 op)
{
	u32 tgid;

	if (!(op_mask & (1U << op)) || !armed)
		return false;
	tgid = current_tgid();
	return tgid != self_tgid && !untracked(tgid);
}

/* Whether `dev` is in the device filter. Constant-folded against .rodata by the verifier. */
static __always_inline bool dev_watched(u32 dev)
{
	u32 n = dev_filter.count;

	if (n == 0)
		return true;
#pragma unroll
	for (u32 i = 0; i < MAX_DEVS; i++) {
		if (i < n && dev_filter.devs[i] == dev)
			return true;
	}
	return false;
}

/* Whether scope_of walks the dentries of `dev` looking for roots, and caches verdicts. */
static __always_inline bool dev_walked(u32 dev)
{
	return scope != SCOPE_ALL && dev_watched(dev);
}

/* Whether a path on `dev` can be in scope. */
static __always_inline bool dev_in_scope(u32 dev)
{
	return scope != SCOPE_ROOTS || dev_watched(dev);
}

/* Whether `sb` exposes kernel state rather than files (proc, sysfs, cgroups, ...) or is
 * internal to the kernel (kern_mount: memfd, pipes, sockets), which no path reaches: out of
 * scope beyond the watch roots. */
static __always_inline bool pseudo_fs(struct super_block *sb)
{
	if (sb->s_flags & SB_KERNMOUNT)
		return true;
	switch (sb->s_magic) {
	case PROC_SUPER_MAGIC:
	case SYSFS_MAGIC:
	case CGROUP_SUPER_MAGIC:
	case CGROUP2_SUPER_MAGIC:
	case DEVPTS_SUPER_MAGIC:
	case DEBUGFS_MAGIC:
	case TRACEFS_MAGIC:
	case BPF_FS_MAGIC:
	case SECURITYFS_MAGIC:
	case PSTOREFS_MAGIC:
	case CONFIGFS_MAGIC:
	case BINFMTFS_MAGIC:
	case MQUEUE_MAGIC:
	case FUSE_CTL_SUPER_MAGIC:
	case SELINUX_MAGIC:
	case SMACK_MAGIC:
		return true;
	}
	return false;
}

struct match {
	struct dentry *d;
	u32 dev;
	u32 depth;
	u32 root;
	u32 _pad;
};

/* One d_parent hop of the scope walk: stop at the first root or exclude, or at the fs root. */
static long match_step(u64 index, void *data)
{
	struct match *m = data;
	struct dentry *d = m->d;
	struct inode *inode = d->d_inode;
	struct dentry *parent;

	if (inode) {
		struct root_key key = { .dev = m->dev, ._pad = 0, .ino = inode->i_ino };
		struct root_val *r = bpf_map_lookup_elem(&roots, &key);

		if (r) {
			m->root = (r->flags & ROOT_F_EXCLUDE) ? ROOT_NONE : r->id;
			return 1;
		}
	}
	parent = d->d_parent;
	if (!parent || parent == d)
		return 1;
	m->d = parent;
	m->depth++;
	return 0;
}

/* Whether `d` on `dev` is in scope, and relative to what: its watch root (with the names up to
 * it), its filesystem root (beyond the watch roots), or nothing (ROOT_NONE). */
static __always_inline struct scope scope_of(struct dentry *d, u32 dev)
{
	struct scope s = { .root = ROOT_NONE, .depth = 0 };
	struct dentry *parent;
	struct inode *inode;
	struct verdict *v, fresh;
	struct match m;
	u64 key, ino, epoch;

	if (scope != SCOPE_ROOTS) {
		if (pseudo_fs(d->d_sb))
			return s;
		s.root = ROOT_FSROOT;
	}
	/* Watch roots: another filesystem is out of scope. Beyond them: one without excludes is
	 * in scope as a whole. */
	if (!dev_walked(dev))
		return s;
	key = (u64)d;
	parent = d->d_parent;
	inode = d->d_inode;
	ino = inode ? inode->i_ino : 0;
	epoch = dir_epoch;
	v = bpf_map_lookup_elem(&verdicts, &key);
	if (v && v->parent == (u64)parent && v->ino == ino && v->epoch == epoch) {
		s.root = v->root;
		s.depth = v->depth;
		return s;
	}
	m.d = d;
	m.dev = dev;
	m.depth = 0;
	m.root = s.root; /* what a walk that meets no root or exclude yields */
	m._pad = 0;
	bpf_loop(SCOPE_WALK_MAX, match_step, &m, 0);
	fresh.parent = (u64)parent;
	fresh.ino = ino;
	fresh.epoch = epoch;
	fresh.root = m.root;
	fresh.depth = m.depth;
	bpf_map_update_elem(&verdicts, &key, &fresh, BPF_ANY);
	s.root = m.root;
	s.depth = m.depth;
	return s;
}

struct walk {
	struct dentry *d;
	u32 end;  /* no name starts at or beyond this offset */
	u32 left; /* names still to emit */
	u32 slot; /* fs_buf slot; its `cur`, `cut` and `top` are the walk's state */
	u32 _pad;
};

/* Emits the name of one dentry, leaf first, and steps to its parent. */
static long walk_step(u64 index, void *data)
{
	struct walk *w = data;
	struct dentry *d = w->d;
	struct dentry *parent = d->d_parent;
	struct fs_scratch *s;
	u32 slot = w->slot, pos;
	long n;

	s = bpf_map_lookup_elem(&fs_buf, &slot);
	if (!s)
		return 1;
	/* The filesystem root has no name. Tested first, so the hop after the last name tells
	 * whether the path is whole. */
	if (!parent || parent == d) {
		s->top = 1;
		return 1;
	}
	if (w->left == 0)
		return 1;
	pos = s->cur;
	if (index == WALK_MAX || pos >= w->end) {
		s->cut = 1;
		return 1;
	}
	/* Bound the write against a constant, never against the running cursor: the logical
	 * cursor stays below two PATH_CAPs, so the clamp never fires. */
	if (pos > FS_DATA_MASK)
		pos = FS_DATA_MASK;
	n = bpf_probe_read_kernel_str(&s->data[pos], NAME_CAP, d->d_name.name);
	if (n <= 0)
		return 1;
	s->cur = pos + n;
	w->left--;
	w->d = parent;
	return 0;
}

/* Writes up to `left` names of `d` and its ancestors, at most WALK_MAX, at `off` in `s`, the
 * scratch of `slot`, and returns the new offset. Sets `trunc` when names are left out, or when
 * `whole` asks for every name up to the filesystem root and the walk did not get there. */
static __always_inline u32 emit_names(struct fs_scratch *s, u32 slot, u32 off, struct dentry *d,
				      u32 left, u32 whole, u32 *trunc)
{
	struct walk w = { .d = d, .end = off + PATH_CAP, .left = left, .slot = slot, ._pad = 0 };

	s->cur = off;
	s->cut = 0;
	s->top = 0;
	/* One hop more than names, for the root test after the last one. The flags are combined
	 * without branches: a branch on them would split every verifier state after the walk. */
	bpf_loop(WALK_MAX + 1, walk_step, &w, 0);
	*trunc |= s->cut | (whole & (s->top ^ 1));
	return s->cur;
}

/* The path of `d`: relative to its watch root when in one, else to its filesystem root. Either
 * keeps its lowest WALK_MAX names, marked truncated when there are more. */
static __always_inline u32 emit_path(struct fs_scratch *s, u32 slot, u32 off, struct dentry *d,
				     struct scope sc, u32 *root, u32 *trunc)
{
	if (sc.root == ROOT_NONE || sc.root == ROOT_FSROOT) {
		*root = ROOT_FSROOT;
		return emit_names(s, slot, off, d, WALK_MAX, 1, trunc);
	}
	*root = sc.root;
	return emit_names(s, slot, off, d, sc.depth, 0, trunc);
}

/* The pid of `task` in its own pid namespace; 0 when that is the initial one. */
static __always_inline u32 ns_pid(struct task_struct *task)
{
	struct pid *pid = task->thread_pid;
	unsigned int level;
	int nr = 0;

	if (!pid)
		return 0;
	level = pid->level;
	/* Namespaces nest at most MAX_PID_NS_LEVEL deep; the bound also lets the verifier accept
	 * the variable index into `numbers`, which is read rather than dereferenced. */
	if (level == 0 || level > MAX_PID_NS_LEVEL)
		return 0;
	bpf_probe_read_kernel(&nr, sizeof(nr), &pid->numbers[level].nr);
	return nr;
}

static __always_inline void fill_task(struct fs_rec *r, u16 op, u64 now)
{
	struct task_struct *leader = bpf_get_current_task_btf()->group_leader;
	u64 id = bpf_get_current_pid_tgid();

	r->hdr.kind = REC_FS;
	r->hdr.op = op;
	r->hdr.flags = 0;
	r->hdr.ts_ns = now;
	r->tgid = id >> 32;
	r->tid = (u32)id;
	r->ns_tgid = ns_pid(leader);
	r->_pad = 0;
	r->start_ns = leader->start_boottime;
	bpf_get_current_comm(r->comm, sizeof(r->comm));
	r->uid = (u32)bpf_get_current_uid_gid();
	r->dev = 0;
	r->ino = 0;
	r->mode = 0;
	r->root = ROOT_NONE;
	r->root2 = ROOT_NONE;
	r->path_len = 0;
	r->path2_len = 0;
	r->aux = 0;
	r->aux2 = 0;
	r->bytes = 0;
	r->file = 0;
}

static __always_inline void submit_fs(struct fs_scratch *s, u32 len)
{
	u64 size = sizeof(s->rec) + (u64)len;

	if (size > sizeof(*s))
		size = sizeof(*s);
	output(s, size);
}

static __always_inline void set_inode(struct fs_rec *r, struct inode *inode)
{
	if (inode) {
		r->ino = inode->i_ino;
		r->mode = inode->i_mode;
	}
}

/*
 * Reports an operation on `d` (path) and optionally a second name `d2` (path2) or a raw
 * string `raw` (path2, ROOT_RAW). In scope when either name is. `mode` overrides the inode's
 * mode when non-zero; `inode` supplies ino and mode (NULL: d's inode). The caller checked
 * reporting(op).
 */
static __always_inline int emit_change(u32 slot, u16 op, struct dentry *d, struct dentry *d2,
				       const char *raw, struct inode *inode, u32 mode, u64 aux,
				       u64 aux2)
{
	struct scope sc, sc2 = { .root = ROOT_NONE, .depth = 0 };
	struct fs_scratch *s;
	u32 dev, trunc = 0, trunc2 = 0, end, end2;
	long n;

	dev = d->d_sb->s_dev;
	sc = scope_of(d, dev);
	if (d2)
		sc2 = scope_of(d2, dev);
	if (sc.root == ROOT_NONE && sc2.root == ROOT_NONE)
		return 0;
	s = bpf_map_lookup_elem(&fs_buf, &slot);
	if (!s)
		return 0;
	fill_task(&s->rec, op, bpf_ktime_get_boot_ns());
	s->rec.dev = dev;
	set_inode(&s->rec, inode ? inode : d->d_inode);
	if (mode)
		s->rec.mode = mode;
	s->rec.aux = aux;
	s->rec.aux2 = aux2;
	end = emit_path(s, slot, 0, d, sc, &s->rec.root, &trunc);
	s->rec.path_len = end;
	end2 = end;
	if (d2) {
		end2 = emit_path(s, slot, end, d2, sc2, &s->rec.root2, &trunc2);
	} else if (raw) {
		n = bpf_probe_read_kernel_str(&s->data[end & FS_DATA_MASK], PATH_CAP, raw);
		if (n > 0) {
			end2 = end + n;
			s->rec.root2 = ROOT_RAW;
		}
	}
	s->rec.path2_len = end2 - end;
	if (trunc)
		s->rec.hdr.flags |= F_PATH_TRUNC;
	if (trunc2)
		s->rec.hdr.flags |= F_PATH2_TRUNC;
	submit_fs(s, end2);
	return 0;
}

/* emit_change() if the current process's `op` is reported. */
static __always_inline int report(u32 slot, u16 op, struct dentry *d, struct dentry *d2,
				  const char *raw, struct inode *inode, u32 mode, u64 aux, u64 aux2)
{
	if (!reporting(op))
		return 0;
	return emit_change(slot, op, d, d2, raw, inode, mode, aux, aux2);
}

/* Whether `d` is still being looked up (d_in_lookup). The flag became `enum dentry_flags`, and
 * moved, in Linux 6.15. */
static __always_inline bool in_lookup(struct dentry *d)
{
	u32 bit = 0x10000000;

	if (bpf_core_enum_value_exists(enum dentry_flags, DCACHE_PAR_LOOKUP))
		bit = bpf_core_enum_value(enum dentry_flags, DCACHE_PAR_LOOKUP);
	return d->d_flags & bit;
}

/*
 * open(O_CREAT) of a name missing from the dentry cache calls this hook (may_o_create) with a
 * dentry that is still in lookup: the file may exist, and then the open creates nothing. Such a
 * create is left to on_file_post_open once that program runs (it needs Linux 6.9). The entry is
 * matched by dentry, not just by thread: the create may run creates of its own in between (an
 * overlay creates the file on its upper layer). A create of the pending dentry decided here (its
 * open failed after the check, and a later one found the name cached) clears the entry so that
 * the open is not reported again. A process that is not reported leaves no entry for
 * on_file_post_open to find.
 */
SEC("fentry/security_inode_create")
int BPF_PROG(on_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 d = (u64)dentry, *pending;

	if (!reporting(OP_CREATE))
		return 0;
	if (creates_confirmed && dev_in_scope(dentry->d_sb->s_dev)) {
		if (in_lookup(dentry)) {
			bpf_map_update_elem(&creating, &tid, &d, BPF_ANY);
			return 0;
		}
		pending = bpf_map_lookup_elem(&creating, &tid);
		if (pending && *pending == d)
			bpf_map_delete_elem(&creating, &tid);
	}
	return emit_change(OP_CREATE, OP_CREATE, dentry, NULL, NULL, NULL, mode | S_IFREG, 0, 0);
}

/* Reports the create of an open that on_create left to it. Runs after every successful open:
 * one that created nothing costs a flag test. */
SEC("fentry/security_file_post_open")
int BPF_PROG(on_file_post_open, struct file *file, int mask)
{
	struct dentry *dentry;
	u64 *pending;
	u32 tid;

	if (!creates_confirmed)
		creates_confirmed = 1;
	if (!(file->f_mode & FMODE_CREATED))
		return 0;
	tid = (u32)bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&creating, &tid);
	dentry = file->f_path.dentry;
	if (!pending || *pending != (u64)dentry)
		return 0;
	bpf_map_delete_elem(&creating, &tid);
	return report(SLOT_POST_OPEN, OP_CREATE, dentry, NULL, NULL, NULL, 0, 0, 0);
}

SEC("fentry/security_inode_mkdir")
int BPF_PROG(on_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return report(OP_MKDIR, OP_MKDIR, dentry, NULL, NULL, NULL, mode | S_IFDIR, 0, 0);
}

SEC("fentry/security_inode_mknod")
int BPF_PROG(on_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	return report(OP_MKNOD, OP_MKNOD, dentry, NULL, NULL, NULL, mode, rdev, 0);
}

SEC("fentry/security_inode_symlink")
int BPF_PROG(on_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	return report(OP_SYMLINK, OP_SYMLINK, dentry, NULL, old_name, NULL, 0, 0, 0);
}

SEC("fentry/security_inode_link")
int BPF_PROG(on_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	return report(OP_LINK, OP_LINK, new_dentry, old_dentry, NULL, old_dentry->d_inode, 0, 0, 0);
}

SEC("fentry/security_inode_unlink")
int BPF_PROG(on_unlink, struct inode *dir, struct dentry *dentry)
{
	return report(OP_UNLINK, OP_UNLINK, dentry, NULL, NULL, NULL, 0, 0, 0);
}

SEC("fentry/security_inode_rmdir")
int BPF_PROG(on_rmdir, struct inode *dir, struct dentry *dentry)
{
	return report(OP_RMDIR, OP_RMDIR, dentry, NULL, NULL, NULL, 0, 0, 0);
}

/* Bumps dir_epoch if renaming `old` onto `new` (`flags` RENAME_*) moves a directory on a
 * watched filesystem: every dentry below it may change scope, whoever moves it. */
static __always_inline void bump_dir_epoch(struct dentry *old, struct dentry *new, u32 flags)
{
	struct inode *src = old->d_inode;
	struct inode *dst = new->d_inode;
	bool moves_dir = (src && S_ISDIR(src->i_mode)) ||
			 ((flags & RENAME_EXCHANGE) && dst && S_ISDIR(dst->i_mode));

	if (moves_dir && dev_walked(old->d_sb->s_dev))
		__sync_fetch_and_add(&dir_epoch, 1);
}

SEC("fentry/security_inode_rename")
int BPF_PROG(on_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	struct inode *src = old_dentry->d_inode;
	struct inode *dst = new_dentry->d_inode;

	bump_dir_epoch(old_dentry, new_dentry, flags);
	return report(OP_RENAME, OP_RENAME, new_dentry, old_dentry, NULL, src, 0, flags,
		      dst ? dst->i_ino : 0);
}

/* The second bump of a directory move, once vfs_rename has made it (see the top comment). The
 * dentries keep their inodes across the move, so the test is on_rename's. */
SEC("fexit/vfs_rename")
int BPF_PROG(on_renamed, struct renamedata *rd, int ret)
{
	if (ret == 0)
		bump_dir_epoch(rd->old_dentry, rd->new_dentry, rd->flags);
	return 0;
}

/* security_inode_setattr is (dentry, attr) upstream before 6.0 and (idmap, dentry, attr) since,
 * and distributions backport the change (EL9's 5.14 has three). The loader sets this from the
 * running kernel's BTF prototype; the verifier sees it as a constant. */
const volatile u32 setattr_idmap = 1;

/*
 * Takes the arguments by hand rather than through BPF_PROG: the verifier refuses a ctx read
 * past the prototype's last argument, so only the branch for this kernel's arity may load
 * them, and the other one is dead code to the verifier. The loads are asm so clang cannot
 * merge the branches into one load at a computed ctx offset, which the verifier refuses too.
 */
SEC("fentry/security_inode_setattr")
int on_setattr(u64 *ctx)
{
	struct dentry *dentry;
	struct iattr *attr;
	unsigned int valid;
	u64 value = 0;
	u16 op;

	if (setattr_idmap)
		asm volatile("%0 = *(u64 *)(%2 + 8)\n\t%1 = *(u64 *)(%2 + 16)"
			     : "=&r"(dentry), "=&r"(attr)
			     : "r"(ctx));
	else
		asm volatile("%0 = *(u64 *)(%2 + 0)\n\t%1 = *(u64 *)(%2 + 8)"
			     : "=&r"(dentry), "=&r"(attr)
			     : "r"(ctx));
	valid = attr->ia_valid;

	if (valid & ATTR_SIZE) {
		op = OP_TRUNCATE;
		value = attr->ia_size;
	} else if (valid & ATTR_MODE) {
		op = OP_CHMOD;
		value = attr->ia_mode;
	} else if (valid & (ATTR_UID | ATTR_GID)) {
		op = OP_CHOWN;
		value = ((u64)attr->ia_uid.val << 32) | attr->ia_gid.val;
	} else if (valid & (ATTR_ATIME | ATTR_MTIME)) {
		op = OP_UTIMES;
	} else {
		op = OP_SETATTR;
	}
	return report(OP_SETATTR, op, dentry, NULL, NULL, NULL, 0, valid, value);
}

/*
 * Whether `file` is overlayfs's own open of a layer's file under the overlay's path, as made
 * before Linux 6.9 (open_with_fake_path, then a backing file keeping the real path aside): its
 * inode is the layer's, not its dentry's. A write or mapping through the overlay's file
 * reaches the hooks again with this one, under another struct file, after the overlay's own
 * was reported. From Linux 6.9 the file has the layer's path, which is out of scope.
 */
static __always_inline bool layer_file(struct file *file)
{
	return file->f_path.dentry->d_inode != file->f_inode;
}

/* When the current open instance of `file` was first seen (see struct file_seen); `now` for
 * one seen for the first time, or whose inode changed under it. */
static __always_inline u64 file_since(struct file *file, struct inode *inode, u64 now)
{
	struct file_seen *f, fresh = { .since = now, .inode = (u64)inode, ._pad = 0 };
	u64 key = (u64)file;

	fresh.gen = inode->i_generation;
	f = bpf_map_lookup_elem(&files, &key);
	if (f && f->inode == fresh.inode && f->gen == fresh.gen)
		return f->since;
	if (!f && bpf_map_update_elem(&files, &key, &fresh, BPF_NOEXIST)) {
		/* Another thread saw it first. */
		f = bpf_map_lookup_elem(&files, &key);
		return f ? f->since : now;
	}
	if (f)
		bpf_map_update_elem(&files, &key, &fresh, BPF_ANY);
	return now;
}

SEC("fentry/rw_verify_area")
int BPF_PROG(on_rw_verify_area, int read_write, struct file *file, const loff_t *ppos, size_t count)
{
	struct write_stash *st;
	u32 zero = 0;

	if (read_write != WRITE)
		return 0;
	st = bpf_map_lookup_elem(&stash, &zero);
	if (!st)
		return 0;
	st->file = (u64)file;
	st->count = count;
	st->tid = (u32)bpf_get_current_pid_tgid();
	return 0;
}

SEC("fentry/security_file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask)
{
	struct write_val *v, fresh;
	struct write_key key;
	struct write_stash *st;
	struct fs_scratch *s;
	struct inode *inode;
	struct dentry *d;
	struct scope sc;
	u32 zero = 0, slot = OP_WRITE, dev, tgid, trunc = 0, end;
	u64 id, bytes = 0, now, ino, since;

	if (!(mask & MAY_WRITE) || !armed)
		return 0;
	inode = file->f_inode;
	if (!inode || (inode->i_mode & S_IFMT) != S_IFREG || layer_file(file))
		return 0;
	/* Most writes are out of scope: turned away before the process and the stash are looked
	 * at. The tracked set, when tracking, turns away more at once. */
	if (track && untracked(current_tgid()))
		return 0;
	d = file->f_path.dentry;
	dev = inode->i_sb->s_dev;
	sc = scope_of(d, dev);
	if (sc.root == ROOT_NONE)
		return 0;
	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;
	if (tgid == self_tgid)
		return 0;
	st = bpf_map_lookup_elem(&stash, &zero);
	if (st && st->file == (u64)file && st->tid == (u32)id) {
		bytes = st->count;
		st->file = 0;
	}

	now = bpf_ktime_get_boot_ns();
	/* Another CPU may have started the instance a moment "later". */
	since = file_since(file, inode, now);
	if (now < since)
		now = since;
	ino = inode->i_ino;
	key.tgid = tgid;
	key._pad = 0;
	key.file = (u64)file;
	v = bpf_map_lookup_elem(&writes, &key);
	/* A binding of an earlier open instance of this struct file is replaced below. */
	if (v && v->first_ns >= since && v->ino == ino && v->dev == dev) {
		__sync_fetch_and_add(&v->bytes, bytes);
		__sync_fetch_and_add(&v->calls, 1);
		v->last_ns = now;
		return 0;
	}
	fresh.dev = dev;
	fresh._pad = 0;
	fresh.ino = ino;
	fresh.bytes = bytes;
	fresh.calls = 1;
	fresh.first_ns = now;
	fresh.last_ns = now;

	s = bpf_map_lookup_elem(&fs_buf, &slot);
	if (!s)
		return 0;
	fill_task(&s->rec, OP_WRITE, now);
	if (v) {
		/* The struct file was freed and reused (for another file, or another open of
		 * this one): hand over the old binding's final totals with the new binding. */
		s->rec.hdr.flags |= F_REPLACED;
		s->rec.aux = v->bytes;
		s->rec.aux2 = v->calls;
		bpf_map_update_elem(&writes, &key, &fresh, BPF_ANY);
	} else if (bpf_map_update_elem(&writes, &key, &fresh, BPF_NOEXIST)) {
		/* Another thread created the binding first: count into it. */
		v = bpf_map_lookup_elem(&writes, &key);
		if (v) {
			__sync_fetch_and_add(&v->bytes, bytes);
			__sync_fetch_and_add(&v->calls, 1);
			v->last_ns = now;
		}
		return 0;
	}
	s->rec.dev = dev;
	s->rec.ino = ino;
	s->rec.mode = inode->i_mode;
	s->rec.bytes = bytes;
	s->rec.file = (u64)file;
	end = emit_path(s, slot, 0, d, sc, &s->rec.root, &trunc);
	s->rec.path_len = end;
	if (trunc)
		s->rec.hdr.flags |= F_PATH_TRUNC;
	submit_fs(s, end);
	return 0;
}

/* A struct file is being freed: its next use is another open instance (see file_seen). Runs
 * on every file release system-wide, so files that cannot carry a binding stop at a flag
 * test and a device compare; the rest cost one map delete. */
SEC("fentry/security_file_free")
int BPF_PROG(on_file_free, struct file *file)
{
	struct inode *inode;
	u64 key = (u64)file;

	if (!(op_mask & (1U << OP_WRITE)) || !(file->f_mode & FMODE_WRITE))
		return 0;
	inode = file->f_inode;
	if (!inode || !dev_in_scope(inode->i_sb->s_dev))
		return 0;
	bpf_map_delete_elem(&files, &key);
	return 0;
}

/*
 * Reports a shared mapping of `file` that became writable (`via` is MAP_VIA_*), once per
 * (tgid, struct file) binding: stores through it change the file without a write call. Kept
 * apart from `writes`, whose bindings userspace coalesces and polls.
 */
static __always_inline int report_mapped(u32 slot, struct file *file, u64 via)
{
	struct mapping *v, fresh;
	struct write_key key;
	struct fs_scratch *s;
	struct inode *inode;
	struct dentry *d;
	struct scope sc;
	u32 dev, tgid, trunc = 0, end;
	u64 ino, start, now, since;

	if (!(op_mask & (1U << OP_WRITE)) || !armed)
		return 0;
	inode = file->f_inode;
	if (!inode || (inode->i_mode & S_IFMT) != S_IFREG || layer_file(file))
		return 0;
	tgid = current_tgid();
	if (tgid == self_tgid || untracked(tgid))
		return 0;
	d = file->f_path.dentry;
	dev = inode->i_sb->s_dev;
	sc = scope_of(d, dev);
	if (sc.root == ROOT_NONE)
		return 0;

	ino = inode->i_ino;
	start = bpf_get_current_task_btf()->group_leader->start_boottime;
	now = bpf_ktime_get_boot_ns();
	since = file_since(file, inode, now);
	if (now < since)
		now = since;
	key.tgid = tgid;
	key._pad = 0;
	key.file = (u64)file;
	v = bpf_map_lookup_elem(&mapped, &key);
	if (v && v->first_ns >= since && v->ino == ino && v->dev == dev && v->start_ns == start)
		return 0;
	fresh.ino = ino;
	fresh.start_ns = start;
	fresh.first_ns = now;
	fresh.dev = dev;
	fresh._pad = 0;
	/* A stale binding is replaced; a new one is reported by the thread that creates it. */
	if (bpf_map_update_elem(&mapped, &key, &fresh, v ? BPF_ANY : BPF_NOEXIST))
		return 0;

	s = bpf_map_lookup_elem(&fs_buf, &slot);
	if (!s)
		return 0;
	fill_task(&s->rec, OP_WRITE, now);
	s->rec.hdr.flags = F_MAPPED;
	s->rec.dev = dev;
	s->rec.ino = ino;
	s->rec.mode = inode->i_mode;
	s->rec.aux = via;
	s->rec.file = (u64)file;
	end = emit_path(s, slot, 0, d, sc, &s->rec.root, &trunc);
	s->rec.path_len = end;
	if (trunc)
		s->rec.hdr.flags |= F_PATH_TRUNC;
	submit_fs(s, end);
	return 0;
}

SEC("fentry/security_mmap_file")
int BPF_PROG(on_mmap_file, struct file *file, unsigned long prot, unsigned long flags)
{
	unsigned long type = flags & MAP_TYPE;

	/* do_mmap refuses a writable shared mapping of a file not open for writing only after
	 * this hook, so that is checked here. */
	if (!file || !(prot & PROT_WRITE) || (type != MAP_SHARED && type != MAP_SHARED_VALIDATE) ||
	    !(file->f_mode & FMODE_WRITE))
		return 0;
	return report_mapped(SLOT_MMAP, file, MAP_VIA_MMAP);
}

SEC("fentry/security_file_mprotect")
int BPF_PROG(on_file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	unsigned long vm_flags = vma->vm_flags;
	struct file *file = vma->vm_file;

	/* A read-only shared mapping turning writable; mprotect checked VM_MAYWRITE before. */
	if (!(prot & PROT_WRITE) || !(vm_flags & VM_SHARED) || (vm_flags & VM_WRITE) || !file)
		return 0;
	return report_mapped(SLOT_MPROTECT, file, MAP_VIA_MPROTECT);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	struct fork_rec r;
	u32 tgid;
	u8 one = 1;

	if (child->pid != child->tgid) /* a thread */
		return 0;
	/* `parent` is the forking task: a tracked process's new processes are tracked, also
	 * those it starts with CLONE_PARENT. */
	if (track) {
		tgid = parent->tgid;
		if (bpf_map_lookup_elem(&tracked, &tgid)) {
			tgid = child->tgid;
			if (bpf_map_update_elem(&tracked, &tgid, &one, BPF_ANY))
				count(STAT_TRACK_FULL);
		}
	}
	r.hdr.kind = REC_FORK;
	r.hdr.op = 0;
	r.hdr.flags = 0;
	r.hdr.ts_ns = bpf_ktime_get_boot_ns();
	r.parent_tgid = parent->tgid;
	r.child_tgid = child->tgid;
	r.child_start_ns = child->start_boottime;
	output(&r, sizeof(r));
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	struct exit_rec r;

	/* Only the last thread: signal->live is already decremented when the tracepoint fires. */
	if (p->signal->live.counter != 0)
		return 0;
	r.hdr.kind = REC_EXIT;
	r.hdr.op = 0;
	r.hdr.flags = 0;
	r.hdr.ts_ns = bpf_ktime_get_boot_ns();
	r.tgid = p->tgid;
	r.code = p->exit_code;
	r.start_ns = p->group_leader->start_boottime;
	output(&r, sizeof(r));
	/* The pid may be reused by a process nobody tracks. */
	if (track) {
		u32 tgid = p->tgid;

		bpf_map_delete_elem(&tracked, &tgid);
	}
	return 0;
}

struct cwd_walk {
	/* Plain addresses read with bpf_probe_read_kernel, not BTF pointers: a mount is reached
	 * from its vfsmount by container_of, which the verifier refuses on BTF pointers. */
	u64 d;        /* the dentry whose name is next */
	u64 mnt;      /* the struct vfsmount it is reached through */
	u64 mnt_root; /* that mount's root dentry */
	u32 done;     /* reached the root of the mount namespace */
	u32 _pad;
};

/* One hop of the cwd walk: emits the name of `d` and steps to its parent or, at the root of a
 * mount, steps to the mountpoint in the parent mount. */
static long cwd_step(u64 index, void *data)
{
	struct cwd_walk *w = data;
	struct dentry *d = (struct dentry *)w->d;
	struct cwd_scratch *s;
	u64 parent = 0, name = 0;
	u32 zero = 0, pos;
	long n;

	if (w->d == w->mnt_root) {
		struct mount *m = container_of((struct vfsmount *)w->mnt, struct mount, mnt);
		struct mount *up = NULL;
		u64 point = 0, root = 0;

		if (bpf_core_read(&up, sizeof(up), &m->mnt_parent))
			return 1;
		/* The namespace root (or a detached tree) is its own parent: the path is whole. */
		if (up == m) {
			w->done = 1;
			return 1;
		}
		if (bpf_core_read(&point, sizeof(point), &m->mnt_mountpoint) ||
		    bpf_core_read(&root, sizeof(root), &up->mnt.mnt_root))
			return 1;
		w->d = point;
		w->mnt = (u64)&up->mnt;
		w->mnt_root = root;
		return 0;
	}
	/* A directory that is its own parent below a mount root is disconnected (unreachable). */
	if (bpf_core_read(&parent, sizeof(parent), &d->d_parent) || parent == w->d)
		return 1;
	s = bpf_map_lookup_elem(&cwd_buf, &zero);
	if (!s)
		return 1;
	pos = s->cur;
	/* A constant bound right before the write; CWD_BYTES leaves NAME_CAP of slack after it. */
	if (pos >= PATH_CAP)
		return 1;
	if (bpf_core_read(&name, sizeof(name), &d->d_name.name))
		return 1;
	n = bpf_probe_read_kernel_str(&s->data[pos], NAME_CAP, (const void *)name);
	if (n <= 0)
		return 1;
	s->cur = pos + n;
	w->d = parent;
	return 0;
}

/*
 * Captures the cwd of an exec for on_exec, which is attached after this program: programs on
 * one tracepoint run in attach order, back to back on one CPU. A separate program, so the
 * walk has its own verifier budget and on_exec loads without it. The walk goes up to the root
 * of the mount namespace, not to the process's root: the same path /proc/<pid>/cwd shows
 * fsblame, also for a chrooted process. No string work: names are emitted leaf first.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec_cwd, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct fs_struct *fs = p->fs;
	struct cwd_scratch *s;
	struct cwd_walk w = {};
	struct vfsmount *mnt;
	u32 zero = 0;

	s = bpf_map_lookup_elem(&cwd_buf, &zero);
	if (!s)
		return 0;
	s->bprm = (u64)bprm;
	s->tgid = p->tgid;
	s->flags = 0;
	s->cur = 0;
	if (bpf_core_read(&w.d, sizeof(w.d), &fs->pwd.dentry) ||
	    bpf_core_read(&w.mnt, sizeof(w.mnt), &fs->pwd.mnt))
		return 0;
	/* Every member access inside bpf_core_read's source gets a CO-RE relocation, so `w.mnt`
	 * is read outside it: the kernel has no struct cwd_walk to relocate against. */
	mnt = (struct vfsmount *)w.mnt;
	if (bpf_core_read(&w.mnt_root, sizeof(w.mnt_root), &mnt->mnt_root))
		return 0;
	bpf_loop(WALK_MAX, cwd_step, &w, 0);
	/* A walk cut short keeps the names it has; one that has none leaves the cwd to /proc. */
	if (w.done)
		s->flags = F_CWD;
	else if (s->cur)
		s->flags = F_CWD | F_CWD_TRUNC;
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	u64 uid_gid = bpf_get_current_uid_gid();
	struct exec_scratch *s;
	struct cwd_scratch *cwd;
	struct exec_rec *r;
	struct mm_struct *mm;
	u64 arg_start, arg_end, env_start, env_end, len, size;
	u32 zero = 0, off;
	long n;

	s = bpf_map_lookup_elem(&exec_buf, &zero);
	if (!s)
		return 0;
	r = &s->rec;
	r->hdr.kind = REC_EXEC;
	r->hdr.op = 0;
	r->hdr.flags = 0;
	r->hdr.ts_ns = bpf_ktime_get_boot_ns();
	r->tgid = p->tgid;
	r->ppid = p->real_parent->tgid;
	r->start_ns = p->group_leader->start_boottime;
	r->cgroup_id = bpf_get_current_cgroup_id();
	r->uid = (u32)uid_gid;
	r->gid = uid_gid >> 32;
	bpf_get_current_comm(r->comm, sizeof(r->comm));

	n = bpf_probe_read_kernel_str(s->data, FILENAME_CAP, bprm->filename);
	off = n > 0 ? n : 0;
	r->filename_len = off;
	r->cwd_len = 0;

	mm = p->mm;
	/* Capture the raw environment (NUL-separated KEY=VAL) in bounded reads. procctx filters
	 * to the keys it wants in userspace, so the kernel does no per-entry scan or string match:
	 * that loop forked verifier state per byte/key and blew the 1M-instruction limit. A longer
	 * environment keeps its head and its tail: tools append their own variables, and npm's
	 * lifecycle variables follow everything they inherit. */
	env_start = mm->env_start;
	env_end = mm->env_end;
	len = env_end > env_start ? env_end - env_start : 0;
	if (len > ENV_CAP) {
		len = ENV_CAP;
		if (bpf_probe_read_user(&s->data[off & EXEC_DATA_MASK], ENV_CAP / 2,
					(const void *)env_start) ||
		    bpf_probe_read_user(&s->data[(off + ENV_CAP / 2) & EXEC_DATA_MASK], ENV_CAP / 2,
					(const void *)(env_end - ENV_CAP / 2)))
			len = 0;
		else
			r->hdr.flags |= F_ENV_TRUNC;
	} else if (bpf_probe_read_user(&s->data[off & EXEC_DATA_MASK], len, (const void *)env_start)) {
		len = 0;
	}
	r->env_len = len;
	off += len;

	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	len = arg_end > arg_start ? arg_end - arg_start : 0;
	if (len > ARGV_CAP) {
		len = ARGV_CAP;
		r->hdr.flags |= F_ARGV_TRUNC;
	}
	if (bpf_probe_read_user(&s->data[off & EXEC_DATA_MASK], len, (const void *)arg_start))
		len = 0;
	r->argv_len = len;
	off += len;

	/* The cwd on_exec_cwd walked for this very exec, if it ran. */
	cwd = bpf_map_lookup_elem(&cwd_buf, &zero);
	if (cwd && cwd->bprm == (u64)bprm && cwd->tgid == r->tgid && (cwd->flags & F_CWD)) {
		len = cwd->cur;
		if (len > CWD_BYTES)
			len = CWD_BYTES;
		if (!bpf_probe_read_kernel(&s->data[off & EXEC_DATA_MASK], len, cwd->data)) {
			r->cwd_len = len;
			r->hdr.flags |= cwd->flags;
			off += len;
		}
	}
	/* Consumed: a later exec that on_exec_cwd misses must not inherit it. */
	if (cwd)
		cwd->bprm = 0;

	size = sizeof(*r) + (u64)off;
	if (size > sizeof(*s))
		size = sizeof(*s);
	output(s, size);
	return 0;
}
