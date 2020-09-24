#include <ioctl.h>
#include <debug.h>
#include <mah_defs.h>
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
		case MAH_IOCTL_CREATE_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			guest_list_lock_write();

			g = (internal_guest*)kmalloc(sizeof(internal_guest), GFP_KERNEL);
			TEST_PTR(g, internal_guest*, guest_list_unlock_write(), -ENOMEM)
			rwlock_init(&g->vcpu_lock);

			g->arch_internal_guest = mah_ops.create_arch_internal_guest();
			TEST_PTR((void*)(g->arch_internal_guest), void*, kfree(g); guest_list_unlock_write(), -ENOMEM)

			if (insert_new_guest(g) == ERROR) {
				kfree(g);
				mah_ops.destroy_arch_internal_guest(g);
				guest_list_unlock_write();
				return -ENOMEM;
			}

			if (kfifo_alloc(&g->pagetables_fifo, MAX_PAGETABLES_COUNT * sizeof(uint64_t), GFP_KERNEL)) {
				kfree(g);
				mah_ops.destroy_arch_internal_guest(g);
				guest_list_unlock_write();
				return -ENOMEM;
			}

			// Return the guest ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&g->id, sizeof(uint64_t))) {
				kfree(g);
				mah_ops.destroy_arch_internal_guest(g);
				guest_list_unlock_write();
				return -EFAULT;
			}

			guest_list_unlock_write();
			break;
		
		case MAH_IOCTL_DESTROY_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			guest_list_lock_write();
			
			if (copy_from_user((void*)&id, (void __user *)argp, sizeof(uint64_t))) {
				guest_list_unlock_read();
				return -EFAULT;
			}

			g = (internal_guest*)kmalloc(sizeof(internal_guest), GFP_KERNEL);
			TEST_PTR(g, internal_guest*, guest_list_unlock_write(), -ENOMEM)
			// Aquire an write lock here. When all VCPUs exit, none of them
			// can be run anymore, because a VPCU run aquires a read lock.
			// Don't unlock it again, it will be eventually destroyed.
			write_lock(&g->vcpu_lock);

			// Destroy all VCPUs first.
			for_every_vcpu(g, (void(*)(internal_vcpu*, void*))mah_ops.destroy_arch_internal_vcpu, NULL);
			for_every_vcpu(g, (void(*)(internal_vcpu*, void*))kfree, NULL);
			for_every_vcpu(g, (void(*)(internal_vcpu*, void*))remove_vcpu, g);

			// Free all other pointers.
			kfree(g);
			mah_ops.destroy_arch_internal_guest(g);
			
			guest_list_unlock_write();
			
			break;
			
		case MAH_IOCTL_CREATE_VCPU:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			guest_list_lock_read();

			g = map_guest_id_to_guest(id_data.guest_id);
			TEST_PTR(g, internal_guest*, guest_list_unlock_write(), -EFAULT)

			vcpu = kmalloc(sizeof(internal_vcpu), GFP_KERNEL);
			TEST_PTR(vcpu, internal_vcpu*,guest_list_unlock_read(), -ENOMEM)

			vcpu->state = VCPU_STATE_CREATED;

			vcpu->arch_internal_vcpu = mah_ops.create_arch_internal_vcpu(g);
			TEST_PTR((void*)(vcpu->arch_internal_vcpu), void*, kfree(vcpu); guest_list_unlock_read(), -ENOMEM)

			write_lock(&g->vcpu_lock);
			
			if (insert_new_vcpu(vcpu, g) == ERROR) {
				write_unlock(&g->vcpu_lock);
				mah_ops.destroy_arch_internal_vcpu(vcpu);
				kfree(vcpu);
				write_unlock(&g->vcpu_lock);
				guest_list_unlock_read();
				return -ENOMEM;
			}

			id_data.vcpu_id = vcpu->id;

			// Return the VCPU ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&id_data, sizeof(user_vcpu_guest_id))) {
				write_unlock(&g->vcpu_lock);
				mah_ops.destroy_arch_internal_vcpu(vcpu);
				kfree(vcpu);
				write_unlock(&g->vcpu_lock);
				guest_list_unlock_read();
				return -ENOMEM;
			}

			write_unlock(&g->vcpu_lock);

			guest_list_unlock_read();
			break;
			
		case MAH_IOCTL_SET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			guest_list_lock_read();
			g = map_guest_id_to_guest(id);
			TEST_PTR(g, internal_guest*, guest_list_unlock_read(), -EFAULT)
			guest_list_unlock_read();

			read_lock(&g->vcpu_lock);
			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			mah_ops.set_vcpu_registers(current_vcpu, &regs);
			read_unlock(&g->vcpu_lock);
			
			break;
			
		case MAH_IOCTL_GET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			guest_list_lock_read();
			g = map_guest_id_to_guest(id);
			TEST_PTR(g, internal_guest*, guest_list_unlock_read(), -EFAULT)
			guest_list_unlock_read();

			read_lock(&g->vcpu_lock);
			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			mah_ops.get_vcpu_registers(current_vcpu, &regs);
			read_unlock(&g->vcpu_lock);

			if (copy_to_user((void __user *)argp, (void*)&regs, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			guest_list_unlock_read();

			break;
			
		case MAH_IOCTL_VCPU_RUN:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			guest_list_lock_read();
			g = map_guest_id_to_guest(id_data.guest_id);
			TEST_PTR(g, internal_guest*, guest_list_unlock_read(), -EFAULT)
			guest_list_unlock_read();

			read_lock(&g->vcpu_lock);
			current_vcpu = map_vcpu_id_to_vcpu(id_data.vcpu_id, g);
			mah_ops.run_vcpu(current_vcpu, g);
			read_unlock(&g->vcpu_lock);

			guest_list_unlock_read();
			
			break;

		case MAH_SET_MEMORY_REGION:
			// TODO: allocate pages array

			if (copy_from_user((void*)&memory_region, (void __user *)argp, sizeof(user_memory_region))) {
				return -EFAULT;
			}

			guest_list_lock_read();
			g = map_guest_id_to_guest(memory_region.guest_id);
			TEST_PTR(g, internal_guest*, guest_list_unlock_read(), -EFAULT)

			current_memory_region = kzalloc(sizeof(internal_memory_region), GFP_KERNEL);
			TEST_PTR(current_memory_region, internal_memory_region*,, -ENOMEM);

			current_memory_region->userspace_addr = memory_region.userspace_addr;
			current_memory_region->guest_addr = memory_region.guest_addr;
			current_memory_region->size = memory_region.size;
			current_memory_region->is_mmio = memory_region.is_mmio;
			current_memory_region->pages = kmalloc_array((int)(memory_region.size / PAGE_SIZE) + 1, sizeof(struct page *), GFP_KERNEL);

			// First check if there already is a memory region which would overlap with the new one
			insert_new_memory_region(current_memory_region, g);

			guest_list_unlock_read();
			break;
			
		default:
			printk(DBG "ioctl command not supported: 0x%x\n", cmd);
			return -EINVAL;
	}
	
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,5,0)
static struct file_operations proc_ctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = unlocked_ioctl,
};
#else
static struct proc_ops proc_ctl_fops = {
	.proc_ioctl = unlocked_ioctl,
};
#endif

void init_ctl_interface(){
    proc_create(PROC_PATH, 0, NULL, &proc_ctl_fops);
}

void finit_ctl_interface(){
    remove_proc_entry(PROC_PATH, NULL);
}
