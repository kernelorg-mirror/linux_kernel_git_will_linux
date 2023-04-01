// SPDX-License-Identifier: GPL-2.0-only

#include <kvm/bpf.h>
#include <kvm/iodev.h>

#include <linux/bpf.h>
#include <linux/eventfd.h>
#include <linux/filter.h>
#include <linux/kvm_host.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>


/*
 * TODO:
 * - Support for IRQ injection via eventfd (see KVM_IRQFD)
 * - Fix build when KVM is modular (bpf_base_func_proto not exported)
 * - Rework to use bpf struct_ops instead of new program types
 */

static const struct bpf_func_proto *
kvm_bpf_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id);
}

static bool kvm_bpf_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	if (off % size != 0)
		return false;

	switch (off) {
	case offsetof(struct bpf_kvm_io_ctx, buf):
		switch (type) {
		case BPF_READ:
			if (prog->type == BPF_PROG_TYPE_KVM_IO_READ)
				return false;

			bpf_ctx_record_field_size(info, sizeof(__u8[8]));
			break;
		case BPF_WRITE:
			if (prog->type == BPF_PROG_TYPE_KVM_IO_WRITE)
				return false;
			break;
		}

		if (!bpf_ctx_narrow_access_ok(off, size, sizeof(__u8[8])))
			return false;
		break;
	case bpf_ctx_range(struct bpf_kvm_io_ctx, offset):
		if (type != BPF_READ)
			return false;

		bpf_ctx_record_field_size(info, sizeof(__u64));
		if (!bpf_ctx_narrow_access_ok(off, size, sizeof(__u64)))
			return false;
		break;
	case offsetof(struct bpf_kvm_io_ctx, len):
		if (type != BPF_READ)
			return false;
		break;
	case bpf_ctx_range(struct bpf_kvm_io_ctx, vcpu_id):
		if (type != BPF_READ)
			return false;

		bpf_ctx_record_field_size(info, sizeof(__u32));
		if (!bpf_ctx_narrow_access_ok(off, size, sizeof(__u32)))
			return false;
		break;
	default:
		return false;
	}

	return true;
}

static u32 kvm_bpf_convert_ctx_access(enum bpf_access_type type,
				      const struct bpf_insn *src,
				      struct bpf_insn *dst,
				      struct bpf_prog *prog,
				      u32 *target_size)
{
	struct bpf_insn *insn = dst;
	int target_off;

	switch (src->off) {
	case offsetof(struct bpf_kvm_io_ctx, buf):
		/* Reads and writes of the transfer buffer are always 64-bit */
		*target_size = 8;
		target_off = offsetof(struct bpf_kvm_io_ctx_kern, val);
		if (type == BPF_READ) {
			*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_kvm_io_ctx_kern, val),
					      src->dst_reg, src->src_reg,
					      target_off);

			*insn++ = BPF_LDX_MEM(BPF_DW, src->dst_reg,
					      src->dst_reg, 0);
		} else {
			*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_kvm_io_ctx_kern, val),
					      src->dst_reg, src->dst_reg,
					      target_off);
			*insn++ = BPF_STX_MEM(BPF_DW, src->dst_reg,
					      src->src_reg, 0);
		}
		break;
	case offsetof(struct bpf_kvm_io_ctx, offset):
		target_off = bpf_target_off(struct bpf_kvm_io_ctx_kern, offset,
					    8, target_size);
		*insn++ = BPF_LDX_MEM(BPF_DW, src->dst_reg, src->src_reg,
				      target_off);
		break;
	case offsetof(struct bpf_kvm_io_ctx, len):
		target_off = bpf_target_off(struct bpf_kvm_io_ctx_kern, len,
					    1, target_size);
		*insn++ = BPF_LDX_MEM(BPF_B, src->dst_reg, src->src_reg,
				      target_off);
		break;
	case offsetof(struct bpf_kvm_io_ctx, vcpu_id):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_kvm_io_ctx_kern, vcpu),
				      src->dst_reg, src->src_reg,
				      offsetof(struct bpf_kvm_io_ctx_kern, vcpu));

		target_off = bpf_target_off(struct kvm_vcpu, vcpu_id,
					    4, target_size);
		*insn++ = BPF_LDX_MEM(BPF_W, src->dst_reg, src->dst_reg,
				      target_off);
		break;
	}

	return insn - dst;
}

const struct bpf_prog_ops kvm_io_prog_ops = { };
const struct bpf_verifier_ops kvm_io_verifier_ops = {
	.get_func_proto		= kvm_bpf_get_func_proto,
	.is_valid_access	= kvm_bpf_is_valid_access,
	.convert_ctx_access	= kvm_bpf_convert_ctx_access,
};

#define KVM_BPF_DEVICE_MAX_REGIONS	1
#define KVM_BPF_DEVICE_MAX_IRQS		1

struct kvm_bpf_device;

struct kvm_bpf_io_region {
	struct kvm_io_device		iodev;
	struct kvm_device		*dev;

	gpa_t				base;

	struct bpf_prog			*read;
	struct bpf_prog			*write;
};

struct kvm_bpf_device {
	struct mutex			lock;

	struct kvm_bpf_io_region	*regions[KVM_BPF_DEVICE_MAX_REGIONS];
	struct eventfd_ctx		*irqs[KVM_BPF_DEVICE_MAX_IRQS];
};

#define to_kvm_bpf_io_region(kvm_io_device)	\
	container_of(kvm_io_device, struct kvm_bpf_io_region, iodev)

static int kvm_bpf_dev_io_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, void *val)
{
	struct kvm_bpf_io_region *reg = to_kvm_bpf_io_region(dev);
	struct bpf_kvm_io_ctx_kern ctx = {
		.dev	= reg->dev,
		.vcpu	= vcpu,
		.offset	= addr - reg->base,
		.len	= len,
		.val	= val,
	};

	if (!reg->read)
		return -ENXIO;

	return bpf_prog_run_pin_on_cpu(reg->read, &ctx);
}

static int kvm_bpf_dev_io_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			        gpa_t addr, int len, const void *val)
{
	struct kvm_bpf_io_region *reg = to_kvm_bpf_io_region(dev);
	struct bpf_kvm_io_ctx_kern ctx = {
		.dev	= reg->dev,
		.vcpu	= vcpu,
		.offset	= addr - reg->base,
		.len	= len,
		.val	= (void *)val,
	};

	if (!reg->write)
		return -ENXIO;

	/* We don't want the BPF program to read uninitialised kernel stack */
	memset((u8 *)val + len, 0, 8 - len);
	return bpf_prog_run_pin_on_cpu(reg->write, &ctx);
}

static void kvm_bpf_dev_io_destructor(struct kvm_io_device *dev)
{
	struct kvm_bpf_io_region *reg = to_kvm_bpf_io_region(dev);

	if (reg->read)
		bpf_prog_put(reg->read);

	if (reg->write)
		bpf_prog_put(reg->write);
}

static struct kvm_io_device_ops kvm_bpf_dev_io_ops = {
	.read		= kvm_bpf_dev_io_read,
	.write		= kvm_bpf_dev_io_write,
	.destructor	= kvm_bpf_dev_io_destructor,
};

static int kvm_bpf_dev_set_region(struct kvm_device *dev, unsigned int idx,
				  struct kvm_bpf_user_region __user *arg)
{
	struct kvm_bpf_device *bpf_dev = dev->private;
	struct kvm_bpf_user_region user_reg;
	struct kvm_bpf_io_region *reg;
	int err = 0;

	if (copy_from_user(&user_reg, arg, sizeof(user_reg)))
		return -EFAULT;

	if (user_reg.addr + user_reg.size < user_reg.addr)
		return -ERANGE;

	reg = kzalloc(sizeof(*reg), GFP_KERNEL_ACCOUNT);
	if (!reg)
		return -ENOMEM;

	if (user_reg.bpf_readfd >= 0) {
		reg->read = bpf_prog_get_type(user_reg.bpf_readfd,
					      BPF_PROG_TYPE_KVM_IO_READ);
		if (IS_ERR(reg->read)) {
			err = PTR_ERR(reg->read);
			reg->read = NULL;
			goto err_cleanup;
		}
	}

	if (user_reg.bpf_writefd >= 0) {
		reg->write = bpf_prog_get_type(user_reg.bpf_writefd,
					       BPF_PROG_TYPE_KVM_IO_WRITE);
		if (IS_ERR(reg->write)) {
			err = PTR_ERR(reg->write);
			reg->write = NULL;
			goto err_cleanup;
		}
	}

	if (!reg->read && !reg->write) {
		err = -EINVAL;
		goto err_cleanup;
	}

	mutex_lock(&bpf_dev->lock);
	if (bpf_dev->regions[idx]) {
		err = -EEXIST;
		goto err_cleanup;
	}

	reg->dev = dev;
	reg->base = user_reg.addr;
	kvm_iodevice_init(&reg->iodev, &kvm_bpf_dev_io_ops);
	mutex_lock(&dev->kvm->slots_lock);
	err = kvm_io_bus_register_dev(dev->kvm, KVM_MMIO_BUS, user_reg.addr,
				      user_reg.size, &reg->iodev);
	mutex_unlock(&dev->kvm->slots_lock);
	if (err)
		goto err_unlock;

	bpf_dev->regions[idx] = reg;
	mutex_unlock(&bpf_dev->lock);
	return 0;

err_unlock:
	mutex_unlock(&bpf_dev->lock);
err_cleanup:
	if (reg->write)
		bpf_prog_put(reg->write);
	if (reg->read)
		bpf_prog_put(reg->read);
	kfree(reg);
	return err;
}

static int kvm_bpf_dev_set_irq(struct kvm_device *dev, unsigned int idx,
			       struct kvm_bpf_user_irq __user *arg)
{
	/* TODO */
	return -EINVAL;
}

static int kvm_bpf_dev_create(struct kvm_device *dev, u32 type)
{
	struct kvm_bpf_device *bpf_dev;

	if (WARN_ON(type != KVM_DEV_TYPE_BPF))
		return -ENODEV;

	bpf_dev = kzalloc(sizeof(*bpf_dev), GFP_KERNEL_ACCOUNT);
	if (!bpf_dev)
		return -ENOMEM;

	mutex_init(&bpf_dev->lock);
	dev->private = bpf_dev;
	return 0;
}

static void kvm_bpf_dev_destroy(struct kvm_device *dev)
{
	struct kvm_bpf_device *bpf_dev = dev->private;
	int i;

	for (i = 0; i < ARRAY_SIZE(bpf_dev->regions); ++i)
		kfree(bpf_dev->regions[i]);

	for (i = 0; i < ARRAY_SIZE(bpf_dev->irqs); ++i)
		kfree(bpf_dev->irqs[i]);

	kfree(bpf_dev);
	kfree(dev);
}

static int kvm_bpf_dev_set_attr(struct kvm_device *dev,
				struct kvm_device_attr *attr)
{
	void __user *uaddr = u64_to_user_ptr(attr->addr);
	struct kvm_bpf_device *bpf_dev = dev->private;

	if (attr->flags)
		return -EINVAL;

	switch (attr->group) {
	case KVM_DEV_BPF_ATTR_GROUP_REGION:
		if (attr->attr >= ARRAY_SIZE(bpf_dev->regions))
			return -ENOENT;

		return kvm_bpf_dev_set_region(dev, attr->attr, uaddr);
	case KVM_DEV_BPF_ATTR_GROUP_IRQ:
		if (attr->attr >= ARRAY_SIZE(bpf_dev->irqs))
			return -ENOENT;

		return kvm_bpf_dev_set_irq(dev, attr->attr, uaddr);
	}

	return -ENXIO;
}

static int kvm_bpf_dev_has_attr(struct kvm_device *dev,
				struct kvm_device_attr *attr)
{
	struct kvm_bpf_device *bpf_dev = dev->private;

	if (attr->flags || attr->addr)
		return -EINVAL;

	switch (attr->group) {
	case KVM_DEV_BPF_ATTR_GROUP_REGION:
		if (attr->attr >= ARRAY_SIZE(bpf_dev->regions))
			return -ENOENT;
		break;
	case KVM_DEV_BPF_ATTR_GROUP_IRQ:
		if (attr->attr >= ARRAY_SIZE(bpf_dev->irqs))
			return -ENOENT;
		break;
	default:
		return -ENXIO;
	}

	return 0;
}

static struct kvm_device_ops kvm_bpf_dev_ops = {
	.name		= "kvm-bpf",
	.create		= kvm_bpf_dev_create,
	.destroy	= kvm_bpf_dev_destroy,
	.set_attr	= kvm_bpf_dev_set_attr,
	.has_attr	= kvm_bpf_dev_has_attr,
};

int kvm_bpf_ops_init(void)
{
	return kvm_register_device_ops(&kvm_bpf_dev_ops, KVM_DEV_TYPE_BPF);
}

void kvm_bpf_ops_exit(void)
{
	kvm_unregister_device_ops(KVM_DEV_TYPE_BPF);
}
