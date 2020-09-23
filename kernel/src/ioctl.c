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

static long unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long argp) {
	int 						i;
	uint64_t					id;
	internal_guest*				g;
	user_arg_registers 			regs;
	internal_vcpu*				vcpu;
	internal_vcpu*				current_vcpu;
	internal_memory_region*		current_memory_region, *current_memory_region_it;
	user_memory_region			memory_region;
	user_vcpu_exit				exit_reason;
	struct list_head*			list_it, *list_it_2;
	
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
				return -ENOMEM;
			}

			// Return the guest ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&g->id, sizeof(int))) {
				guest_list_unlock_write();
				return -EFAULT;
			}

			rwlock_init(&g->vcpu_lock);

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

			// TODO: Destroy all memory regions.

			// Free all other pointers.
			kfree(g);
			mah_ops.destroy_arch_internal_guest(g);
			
			guest_list_unlock_write();
			
			break;
			
		case MAH_IOCTL_CREATE_VCPU:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id, (void __user *)argp, sizeof(uint64_t))) {
				return -EFAULT;
			}

			guest_list_lock_read();

			g = map_guest_id_to_guest(id);
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

			break;
			
		case MAH_IOCTL_VCPU_RUN:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			/*guest_lock_read();

			TEST_PTR(guest, internal_guest*, guest_unlock_read());
			TEST_PTR(guest->vcpus, internal_vcpu*, guest_unlock_read());
			TEST_PTR(argp, unsigned long, guest_unlock_read());
			TEST_PTR(guest->vcpus->vcpu_vmcb, vmcb*, guest_unlock_read());
			TEST_PTR(guest->vcpus->host_vmcb, vmcb*, guest_unlock_read());
			TEST_PTR(guest->vcpus->vcpu_regs, gp_regs*, guest_unlock_read());
			
			if (copy_from_user((void*)&exit_reason, (void __user *)argp, sizeof(user_vcpu_exit))) return -EFAULT;

			current_vcpu = map_vcpu_id_to_vcpu(exit_reason.vcpu_id, guest);
			
			exit_reason = run_vcpu(current_vcpu);
			
			if (map_vcpu_id_to_vcpu(exit_reason.vcpu_id, guest)->state == VCPU_STATE_FAILED) {
				guest_unlock_read();
				return -EAGAIN;
			}
			
			if (copy_to_user((void __user *)argp, (void*)&exit_reason, sizeof(user_vcpu_exit))) {
				guest_unlock_read();
				return -EFAULT;
			}

			guest_unlock_read();*/
			
			break;

		case MAH_SET_MEMORY_REGION:
			/*guest_lock_write();

			current_memory_region = kzalloc(sizeof(internal_memory_region), GFP_KERNEL);
			TEST_PTR(current_memory_region, internal_memory_region*, guest_unlock_write());

			if (copy_from_user((void*)&memory_region, (void __user *)argp, sizeof(user_memory_region))) {
				guest_unlock_write();
				return -EFAULT;
			}

			current_memory_region->userspace_addr = memory_region.userspace_addr;
			current_memory_region->guest_addr = memory_region.guest_addr;
			current_memory_region->size = memory_region.size;
			current_memory_region->is_mmio = memory_region.is_mmio;

			// First check if there already is a memory region which would overlap with the new one
			if (guest->memory_regions != NULL) {
				list_for_each(list_it, &guest->memory_regions->list) {
					current_memory_region_it = list_entry(list_it, internal_memory_region, list);

					if ((current_memory_region_it->guest_addr <= current_memory_region->guest_addr) && 
							(current_memory_region_it->guest_addr + current_memory_region_it->size >= current_memory_region->guest_addr)) {
						kfree(current_memory_region);
						guest_unlock_write();
						return -EFAULT;
					}
				}
			}

			// Initialize the list head in case this is the first memory region
			if (guest->memory_regions == NULL) {
				guest->memory_regions = current_memory_region;
				INIT_LIST_HEAD(&current_memory_region->list);
			} else {
				list_add(&current_memory_region->list, &guest->memory_regions->list);
			}

			guest_unlock_write();*/
			break;
			
		default:
			printk(DBG "ioctl command not supported: 0x%x\n", cmd);
			return -EINVAL;
	}
	
	return 0;
}

static struct file_operations proc_ctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = unlocked_ioctl,
};

void init_ctl_interface(){
    proc_create(PROC_PATH, 0, NULL, &proc_ctl_fops);
}

void finit_ctl_interface(){
    remove_proc_entry(PROC_PATH, NULL);
}
