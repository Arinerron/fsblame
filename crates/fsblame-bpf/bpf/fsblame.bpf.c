// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * fsblame's tracer: reports modifying operations on watched paths with the acting process,
 * and streams fork/exec/exit so userspace can rebuild lineage (procctx).
 *
 * Scope: a dentry is in scope when it, or its nearest ancestor found in `roots`, is a watch
 * root (not an exclude). The verdict is cached per dentry in `verdicts`, validated against the
 * dentry's parent, inode number and `dir_epoch` (bumped whenever a directory is renamed on a
 * watched filesystem), so an unwatched path costs one device check and one LRU lookup.
 *
 * Writes: rw_verify_area stashes the requested byte count per CPU; the security_file_permission
 * hook that follows consumes it and accumulates into `writes`, keyed by (tgid, struct file *).
 * Only the first write of a binding produces a record; userspace drains the totals.
 *
 * Every program owns one `fs_buf` slot (its op), so programs never share scratch space: the
 * same program cannot nest on one CPU (the kernel skips recursive runs).
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

/* Payload offsets are masked or clamped to a constant before every write so the verifier can
 * bound them; the logical offsets never reach the mask (two paths of PATH_CAP + NAME_CAP, or
 * one exec record), so the masking never wraps. The slack after the mask covers the largest
 * single write. */
#define FS_DATA_MASK 4095
#define FS_DATA_BYTES (FS_DATA_MASK + 1 + PATH_CAP)
#define EXEC_DATA_MASK 16383
#define EXEC_DATA_BYTES (EXEC_DATA_MASK + 1 + ENV_CAP)
_Static_assert(ENV_CAP >= ARGV_CAP, "the exec slack covers the larger of env and argv");
_Static_assert(FILENAME_CAP + ENV_CAP + ARGV_CAP <= EXEC_DATA_MASK, "exec offsets never wrap");

struct fs_scratch {
	struct fs_rec rec;
	u8 data[FS_DATA_BYTES];
	/* Write cursor of the path walk in `data`. It lives in the map value, not in the walk's
	 * stack context, because the verifier does not track map contents: every walk_step
	 * iteration then starts from the same state and bpf_loop converges after one pass.
	 * Tracked on the stack, each iteration's cursor range is a new state; two walks in one
	 * program (rename, link) multiplied past the 1M-instruction limit. */
	u32 cur;
	u32 _pad;
};

struct exec_scratch {
	struct exec_rec rec;
	u8 data[EXEC_DATA_BYTES];
};

/* Byte count of the write in flight on this CPU, from rw_verify_area. */
struct write_stash {
	u64 file;
	u64 count;
	u32 tid;
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

/* Bumped on every directory rename on a watched filesystem: invalidates all verdicts. */
u64 dir_epoch = 0;

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
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct write_stash);
} stash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, OP_COUNT); /* one slot per program, indexed by its op */
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
	__uint(max_entries, STAT_COUNT);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

static __always_inline u32 current_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline void output(void *data, u64 size)
{
	if (bpf_ringbuf_output(&events, data, size, 0)) {
		u32 slot = STAT_RING_DROPS;
		u64 *n = bpf_map_lookup_elem(&stats, &slot);

		if (n)
			*n += 1;
	}
}

/* Whether `dev` holds a watch root. Constant-folded against .rodata by the verifier. */
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

static __always_inline struct scope scope_of(struct dentry *d, u32 dev)
{
	struct scope s = { .root = ROOT_NONE, .depth = 0 };
	struct dentry *parent;
	struct inode *inode;
	struct verdict *v, fresh;
	struct match m;
	u64 key, ino, epoch;

	if (!dev_watched(dev))
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
	m.root = ROOT_NONE;
	m._pad = 0;
	bpf_loop(WALK_MAX, match_step, &m, 0);
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
	u32 slot; /* fs_buf slot; its `cur` is the write cursor */
	u32 trunc;
};

/* Emits the name of one dentry, leaf first, and steps to its parent. */
static long walk_step(u64 index, void *data)
{
	struct walk *w = data;
	struct dentry *d = w->d;
	struct dentry *parent;
	struct fs_scratch *s;
	u32 slot = w->slot, pos;
	long n;

	if (w->left == 0)
		return 1;
	parent = d->d_parent;
	if (!parent || parent == d) /* the filesystem root has no name */
		return 1;
	s = bpf_map_lookup_elem(&fs_buf, &slot);
	if (!s)
		return 1;
	pos = s->cur;
	if (pos >= w->end) {
		w->trunc = 1;
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

/* Writes up to `left` names of `d` and its ancestors at `off` in `s`, the scratch of `slot`;
 * returns the new offset. */
static __always_inline u32 emit_names(struct fs_scratch *s, u32 slot, u32 off, struct dentry *d,
				      u32 left, u32 *trunc)
{
	struct walk w = {
		.d = d, .end = off + PATH_CAP, .left = left, .slot = slot, .trunc = 0,
	};

	s->cur = off;
	bpf_loop(WALK_MAX, walk_step, &w, 0);
	/* A walk to the fs root that used every hop may have stopped short of it. */
	if (w.trunc || (left == WALK_MAX && w.left == 0))
		*trunc = 1;
	return s->cur;
}

/* The path of `d`: relative to its watch root when in scope, else to its filesystem root. */
static __always_inline u32 emit_path(struct fs_scratch *s, u32 slot, u32 off, struct dentry *d,
				     struct scope sc, u32 *root, u32 *trunc)
{
	if (sc.root == ROOT_NONE) {
		*root = ROOT_FSROOT;
		return emit_names(s, slot, off, d, WALK_MAX, trunc);
	}
	*root = sc.root;
	return emit_names(s, slot, off, d, sc.depth, trunc);
}

static __always_inline void fill_task(struct fs_rec *r, u16 op, u64 now)
{
	struct task_struct *task = bpf_get_current_task_btf();
	u64 id = bpf_get_current_pid_tgid();

	r->hdr.kind = REC_FS;
	r->hdr.op = op;
	r->hdr.flags = 0;
	r->hdr.ts_ns = now;
	r->tgid = id >> 32;
	r->tid = (u32)id;
	r->start_ns = task->group_leader->start_boottime;
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
 * mode when non-zero; `inode` supplies ino and mode (NULL: d's inode).
 */
static __always_inline int report(u32 slot, u16 op, struct dentry *d, struct dentry *d2,
				  const char *raw, struct inode *inode, u32 mode, u64 aux, u64 aux2)
{
	struct scope sc, sc2 = { .root = ROOT_NONE, .depth = 0 };
	struct fs_scratch *s;
	u32 dev, trunc = 0, trunc2 = 0, end, end2;
	long n;

	if (!(op_mask & (1U << op)) || current_tgid() == self_tgid)
		return 0;
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

SEC("fentry/security_inode_create")
int BPF_PROG(on_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return report(OP_CREATE, OP_CREATE, dentry, NULL, NULL, NULL, mode | S_IFREG, 0, 0);
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

SEC("fentry/security_inode_rename")
int BPF_PROG(on_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	struct inode *src = old_dentry->d_inode;
	struct inode *dst = new_dentry->d_inode;
	bool moves_dir = (src && S_ISDIR(src->i_mode)) ||
			 ((flags & RENAME_EXCHANGE) && dst && S_ISDIR(dst->i_mode));

	/* Every dentry below a moved directory may change scope. */
	if (moves_dir && dev_watched(old_dentry->d_sb->s_dev))
		__sync_fetch_and_add(&dir_epoch, 1);
	return report(OP_RENAME, OP_RENAME, new_dentry, old_dentry, NULL, src, 0, flags,
		      dst ? dst->i_ino : 0);
}

SEC("fentry/security_inode_setattr")
int BPF_PROG(on_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
	unsigned int valid = attr->ia_valid;
	u64 value = 0;
	u16 op;

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
	u64 id, bytes = 0, now, ino;

	if (!(mask & MAY_WRITE))
		return 0;
	inode = file->f_inode;
	if (!inode || (inode->i_mode & S_IFMT) != S_IFREG)
		return 0;
	id = bpf_get_current_pid_tgid();
	st = bpf_map_lookup_elem(&stash, &zero);
	if (st && st->file == (u64)file && st->tid == (u32)id) {
		bytes = st->count;
		st->file = 0;
	}
	tgid = id >> 32;
	if (tgid == self_tgid)
		return 0;
	d = file->f_path.dentry;
	dev = inode->i_sb->s_dev;
	sc = scope_of(d, dev);
	if (sc.root == ROOT_NONE)
		return 0;

	now = bpf_ktime_get_boot_ns();
	ino = inode->i_ino;
	key.tgid = tgid;
	key._pad = 0;
	key.file = (u64)file;
	v = bpf_map_lookup_elem(&writes, &key);
	if (v && v->ino == ino && v->dev == dev) {
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
		/* The struct file was freed and reused for another inode: hand over the old
		 * binding's final totals with the new binding. */
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

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	struct fork_rec r;

	if (child->pid != child->tgid) /* a thread */
		return 0;
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
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	u64 uid_gid = bpf_get_current_uid_gid();
	struct exec_scratch *s;
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
	r->_pad = 0;

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

	size = sizeof(*r) + (u64)off;
	if (size > sizeof(*s))
		size = sizeof(*s);
	output(s, size);
	return 0;
}
