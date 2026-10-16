// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * Feature probes for `fsblame doctor`: one program per attach point fsblame uses, named
 * `probe_<function>` for fentry and `probe_<tracepoint>` for tp_btf. The sched probes make the
 * CO-RE accesses the tracer relies on; nothing is output.
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Written so the probed loads are not optimised away; never read. Pointers themselves are
 * never mixed in: the verifier forbids arithmetic on them. */
u64 sink = 0;

#define PROBE_FENTRY(fn)                   \
	SEC("fentry/" #fn)                 \
	int probe_##fn(void *ctx)          \
	{                                  \
		return 0;                  \
	}

PROBE_FENTRY(security_file_permission)
PROBE_FENTRY(rw_verify_area)
PROBE_FENTRY(security_inode_create)
PROBE_FENTRY(security_inode_mkdir)
PROBE_FENTRY(security_inode_mknod)
PROBE_FENTRY(security_inode_symlink)
PROBE_FENTRY(security_inode_link)
PROBE_FENTRY(security_inode_rmdir)
PROBE_FENTRY(security_inode_rename)
PROBE_FENTRY(security_inode_setattr)

SEC("fentry/security_inode_unlink")
int BPF_PROG(probe_security_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	sink = dentry->d_parent->d_inode->i_ino ^ dentry->d_sb->s_dev;
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(probe_sched_process_exec, struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	sink = p->mm->arg_start ^ p->group_leader->start_boottime ^
	       p->fs->pwd.dentry->d_inode->i_ino;
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(probe_sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	sink = child->start_boottime ^ parent->tgid;
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(probe_sched_process_exit, struct task_struct *p)
{
	sink = p->signal->live.counter ^ p->exit_code;
	return 0;
}
