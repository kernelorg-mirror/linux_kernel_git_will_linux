/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_BPF_H
#define __KVM_BPF_H

#include <linux/types.h>

#ifdef CONFIG_BPF_SYSCALL
struct bpf_kvm_io_ctx_kern {
	struct kvm_device		*dev;
	struct kvm_vcpu			*vcpu;

	u64				offset;
	u8				len;
	void				*val;
};

int kvm_bpf_ops_init(void);
void kvm_bpf_ops_exit(void);
#else
static inline int kvm_bpf_ops_init(void)
{
	return 0;
}

static inline void kvm_bpf_ops_exit(void)
{
}
#endif /* CONFIG_BPF_SYSCALL */

#endif /* __KVM_BPF_H */
