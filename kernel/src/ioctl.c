#include <ioctl.h>
#include <stddef.h>
#include <hyperkraken_defs.h>
#include <guest.h>
#include <memory.h>
#include <svm/svm.h>

#include <asm/pgtable.h>
#include <linux/slab.h> 
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/rwsem.h>

static long unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long argp) {
	uint64_t					id;
	internal_guest				*g;
	internal_vcpu				*vcpu;
	internal_vcpu				*current_vcpu;
	internal_memory_region		*current_memory_region;

	user_arg_registers 			regs;
	user_memory_region			memory_region;
	user_vcpu_guest_id			id_data;
	
	printk(DBG "Got ioctl cmd: 0x%x\n", cmd);
	
	switch (cmd) {
		case HYPERKRAKEN_IOCTL_CREATE_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			g = create_guest();

			if (g == NULL) {
				destroy_guest(g);
				return -ENOMEM;
			}

			guest_list_lock();

			if (insert_new_guest(g)) {
				guest_list_unlock();
				destroy_guest(g);
				return -ENOMEM;
			}

			guest_list_unlock();

			// Return the guest ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&g->id, sizeof(uint64_t))) {
				destroy_guest(g);
				return -EFAULT;
			}
			break;
		
		case HYPERKRAKEN_IOCTL_DESTROY_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)
			
			if (copy_from_user((void*)&id, (void __user *)argp, sizeof(uint64_t))) {
				return -EFAULT;
			}

			guest_list_lock();

			g = map_guest_id_to_guest(id);
			TEST_PTR(g, internal_guest*, guest_list_unlock(), -EINVAL)

			// Aquire a write lock here in order to prevent VCPUs from running.
			guest_vcpu_write_lock(g);

			destroy_guest(g);

			guest_list_unlock();
			
			break;
			
		case HYPERKRAKEN_IOCTL_CREATE_VCPU:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(id_data.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)

			guest_vcpu_write_lock(g);
			vcpu = kmalloc(sizeof(internal_vcpu), GFP_KERNEL);
			TEST_PTR(vcpu, internal_vcpu*, guest_vcpu_write_unlock(g), -ENOMEM)

			vcpu->state = VCPU_STATE_CREATED;

			vcpu->arch_internal_vcpu = hyperkraken_ops.create_arch_internal_vcpu(g);
			TEST_PTR((void*)(vcpu->arch_internal_vcpu), void*, kfree(vcpu); guest_vcpu_write_unlock(g), -ENOMEM)
			
			if (insert_new_vcpu(vcpu, g)) {
				hyperkraken_ops.destroy_arch_internal_vcpu(vcpu);
				kfree(vcpu);
				guest_vcpu_write_unlock(g);
				return -ENOMEM;
			}

			id_data.vcpu_id = vcpu->id;

			// Return the VCPU ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&id_data, sizeof(user_vcpu_guest_id))) {
				hyperkraken_ops.destroy_arch_internal_vcpu(vcpu);
				kfree(vcpu);
				guest_vcpu_write_unlock(g);
				return -ENOMEM;
			}

			guest_vcpu_write_unlock(g);

			break;
			
		case HYPERKRAKEN_IOCTL_SET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(regs.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)
			
			guest_vcpu_read_lock(g);
			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			hyperkraken_ops.set_vcpu_registers(current_vcpu, &regs);
			guest_vcpu_read_unlock(g);
			
			break;
			
		case HYPERKRAKEN_IOCTL_GET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(regs.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)

			guest_vcpu_read_lock(g);
			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			hyperkraken_ops.get_vcpu_registers(current_vcpu, &regs);
			guest_vcpu_read_unlock(g);

			if (copy_to_user((void __user *)argp, (void*)&regs, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			break;
			
		case HYPERKRAKEN_IOCTL_VCPU_RUN:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(id_data.guest_id);
			guest_list_unlock();
			TEST_PTR(g, internal_guest*,, -EINVAL)

			guest_vcpu_read_lock(g);
			current_vcpu = map_vcpu_id_to_vcpu(id_data.vcpu_id, g);
			hyperkraken_ops.run_vcpu(current_vcpu, g);
			guest_vcpu_read_unlock(g);
			
			break;

		case HYPERKRAKEN_SET_MEMORY_REGION:
			if (copy_from_user((void*)&memory_region, (void __user *)argp, sizeof(user_memory_region))) {
				return -EFAULT;
			}

			guest_list_lock();
			g = map_guest_id_to_guest(memory_region.guest_id);
			TEST_PTR(g, internal_guest*, guest_list_unlock(), -EINVAL)

			current_memory_region = kzalloc(sizeof(internal_memory_region), GFP_KERNEL);
			TEST_PTR(current_memory_region, internal_memory_region*, guest_list_unlock(), -ENOMEM);

			current_memory_region->userspace_addr 	= memory_region.userspace_addr;
			current_memory_region->guest_addr 		= memory_region.guest_addr;
			current_memory_region->size 			= memory_region.size;
			current_memory_region->is_mmio			= memory_region.is_mmio;
			current_memory_region->is_cow			= memory_region.is_cow;
			current_memory_region->pages 			= kzalloc((int)((memory_region.size / PAGE_SIZE) + 1) * sizeof(struct page *), GFP_KERNEL);
			current_memory_region->modified_pages	= kzalloc((int)((memory_region.size / PAGE_SIZE) + 1) * sizeof(void*), GFP_KERNEL);

			// First check if there already is a memory region which would overlap with the new one
			mmu_add_memory_region(g->mmu, current_memory_region);

			guest_list_unlock();

			break;
			
		default:
			printk(DBG "ioctl command not supported: 0x%x\n", cmd);
			return -EINVAL;
	}
	
	return 0;
}

static struct proc_ops proc_ctl_fops = {
	.proc_ioctl = unlocked_ioctl,
};

void init_ctl_interface(){
    proc_create(PROC_PATH, 0, NULL, &proc_ctl_fops);
}

void finit_ctl_interface(){
    remove_proc_entry(PROC_PATH, NULL);
}
