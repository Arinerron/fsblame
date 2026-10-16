/* Hand-written subset of vmlinux.h: only what fsblame's BPF programs and the libbpf headers
 * need.
 *
 * Field order and offsets are deliberately NOT the kernel's. Every record below is
 * preserve_access_index, so clang emits a CO-RE relocation for each field access and aya
 * rewrites it against /sys/kernel/btf/vmlinux at load time. Matching is by type name (minus any
 * ___flavor suffix) and field name; anonymous structs and unions in the kernel type (dentry's
 * d_name, file's f_path, iattr's ia_uid, mm_struct's arg_start on 7.x, vm_area_struct's
 * vm_flags since 6.3) are looked through, and const/typedef wrappers are skipped.
 */
#ifndef __VMLINUX_MIN_H__
#define __VMLINUX_MIN_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef _Bool bool;
#define true 1
#define false 0
typedef int pid_t;
typedef unsigned short umode_t;
typedef __u32 dev_t;
typedef long long loff_t;
typedef unsigned long size_t;

/* UAPI values (stable ABI); vmlinux.h would supply these. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

struct mnt_idmap;
struct pid_namespace;
struct pt_regs;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	unsigned int val;
} kuid_t;

typedef struct {
	unsigned int val;
} kgid_t;

struct qstr {
	const unsigned char *name;
};

struct super_block {
	dev_t s_dev;
};

struct inode {
	umode_t i_mode;
	unsigned long i_ino;
	struct super_block *i_sb;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	struct super_block *d_sb;
};

struct vfsmount {
	struct dentry *mnt_root;
};

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	unsigned int f_mode;
	struct path f_path;
	struct inode *f_inode;
};

struct vm_area_struct {
	unsigned long vm_flags;
	struct file *vm_file;
};

struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	kuid_t ia_uid;
	kgid_t ia_gid;
	loff_t ia_size;
};

struct fs_struct {
	struct path pwd;
};

/* `pid->numbers` is indexed at run time, which strides by this local size: both fields keep it
 * equal to the kernel's. */
struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct pid {
	unsigned int level;
	struct upid numbers[];
};

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
	unsigned long env_start;
	unsigned long env_end;
};

struct signal_struct {
	atomic_t live;
};

struct task_struct {
	pid_t pid;
	pid_t tgid;
	int exit_code;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct pid *thread_pid;
	u64 start_boottime;
	struct mm_struct *mm;
	struct fs_struct *fs;
	struct signal_struct *signal;
};

struct linux_binprm {
	const char *filename;
};

#pragma clang attribute pop

#endif /* __VMLINUX_MIN_H__ */
