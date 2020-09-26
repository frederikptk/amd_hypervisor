#include <ioctl.h>
#include <stddef.h>
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

void destroy_guest(internal_guest *g) {
	if (g != NULL) {
		// Destroy all VCPUs first.
		for_every_vcpu(g, (void(*)(internal_vcpu*, void*))mah_ops.destroy_arch_internal_vcpu, NULL);
		for_every_vcpu(g, (void(*)(internal_vcpu*, void*))remove_vcpu, g);
		for_every_vcpu(g, (void(*)(internal_vcpu*, void*))kfree, NULL);

		// Destroy the MMU: pagetables, memory regions, internals
		if (g->mmu != NULL) {
			mah_ops.destroy_mmu(g->mmu);
			mmu_destroy_all_memory_regions(g->mmu);
			mmu_destroy_all_pagetables(g->mmu);
			kfree(g->mmu);
		}

		// Free all other pointers.
		mah_ops.destroy_arch_internal_guest(g);
		remove_guest(g);
		kfree(g);
	}
}

internal_guest* create_guest(void) {
	internal_guest				*g;
	internal_mmu				*mmu;

	// Create the guest itself
	g = (internal_guest*)kmalloc(sizeof(internal_guest), GFP_KERNEL);
	if (g == NULL) goto err;

	// Create the MMU for the guest
	mmu = kmalloc(sizeof(internal_mmu), GFP_KERNEL);
	if (mmu == NULL) goto err;
	mah_ops.init_mmu(mmu);
	g->mmu = mmu;

	// Initialize the arch-dependent structure for the guest
	g->arch_internal_guest = mah_ops.create_arch_internal_guest(g);
	if (g->arch_internal_guest == NULL) goto err;

	return g;

err:
	destroy_guest(g);
	return NULL;
}

static long unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long argp) {
	uint64_t					id;
	internal_guest				*g;
	internal_vcpu				*vcpu;
	internal_vcpu				*current_vcpu;
	internal_memory_region		*current_memory_region;
	internal_mmu				*mmu;

	user_arg_registers 			regs;
	user_memory_region			memory_region;
	user_vcpu_guest_id			id_data;
	
	printk(DBG "Got ioctl cmd: 0x%x\n", cmd);
	
	switch (cmd) {
		case MAH_IOCTL_CREATE_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			g = create_guest();

			if (g == NULL) {
				destroy_guest(g);
				return -ENOMEM;
			}

			if (insert_new_guest(g) == ERROR) {
				destroy_guest(g);
				return -ENOMEM;
			}

			// Return the guest ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&g->id, sizeof(uint64_t))) {
				destroy_guest(g);
				return -EFAULT;
			}
			break;
		
		case MAH_IOCTL_DESTROY_GUEST:
			TEST_PTR(argp, unsigned long,,-EFAULT)
			
			if (copy_from_user((void*)&id, (void __user *)argp, sizeof(uint64_t))) {
				return -EFAULT;
			}

			g = map_guest_id_to_guest(id);
			TEST_PTR(g, internal_guest*,, -EINVAL)

			destroy_guest(g);
			
			break;
			
		case MAH_IOCTL_CREATE_VCPU:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			g = map_guest_id_to_guest(id_data.guest_id);
			TEST_PTR(g, internal_guest*,, -EINVAL)

			vcpu = kmalloc(sizeof(internal_vcpu), GFP_KERNEL);
			TEST_PTR(vcpu, internal_vcpu*,, -ENOMEM)

			vcpu->state = VCPU_STATE_CREATED;

			vcpu->arch_internal_vcpu = mah_ops.create_arch_internal_vcpu(g);
			TEST_PTR((void*)(vcpu->arch_internal_vcpu), void*, kfree(vcpu);, -ENOMEM)
			
			if (insert_new_vcpu(vcpu, g) == ERROR) {
				mah_ops.destroy_arch_internal_vcpu(vcpu);
				kfree(vcpu);
				return -ENOMEM;
			}

			id_data.vcpu_id = vcpu->id;

			// Return the VCPU ID to the user.
			if (copy_to_user((void __user *)argp, (void*)&id_data, sizeof(user_vcpu_guest_id))) {
				mah_ops.destroy_arch_internal_vcpu(vcpu);
				kfree(vcpu);
				return -ENOMEM;
			}
			break;
			
		case MAH_IOCTL_SET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			g = map_guest_id_to_guest(regs.guest_id);
			TEST_PTR(g, internal_guest*,, -EINVAL)
			
			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			mah_ops.set_vcpu_registers(current_vcpu, &regs);
			
			break;
			
		case MAH_IOCTL_GET_REGISTERS:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			g = map_guest_id_to_guest(regs.guest_id);
			TEST_PTR(g, internal_guest*,, -EINVAL)

			current_vcpu = map_vcpu_id_to_vcpu(regs.vcpu_id, g);
			mah_ops.get_vcpu_registers(current_vcpu, &regs);

			if (copy_to_user((void __user *)argp, (void*)&regs, sizeof(user_arg_registers))) {
				return -EFAULT;
			}

			break;
			
		case MAH_IOCTL_VCPU_RUN:
			TEST_PTR(argp, unsigned long,,-EFAULT)

			if (copy_from_user((void*)&id_data, (void __user *)argp, sizeof(user_vcpu_guest_id))) {
				return -EFAULT;
			}

			g = map_guest_id_to_guest(id_data.guest_id);
			TEST_PTR(g, internal_guest*,, -EINVAL)

			current_vcpu = map_vcpu_id_to_vcpu(id_data.vcpu_id, g);
			mah_ops.run_vcpu(current_vcpu, g);
			
			break;

		case MAH_SET_MEMORY_REGION:
			// TODO: allocate pages array

			if (copy_from_user((void*)&memory_region, (void __user *)argp, sizeof(user_memory_region))) {
				return -EFAULT;
			}

			g = map_guest_id_to_guest(memory_region.guest_id);
			TEST_PTR(g, internal_guest*,, -EINVAL)

			current_memory_region = kzalloc(sizeof(internal_memory_region), GFP_KERNEL);
			TEST_PTR(current_memory_region, internal_memory_region*,, -ENOMEM);

			current_memory_region->userspace_addr 	= memory_region.userspace_addr;
			current_memory_region->guest_addr 		= memory_region.guest_addr;
			current_memory_region->size 			= memory_region.size;
			current_memory_region->is_mmio			= memory_region.is_mmio;
			current_memory_region->pages 			= kmalloc_array((int)(memory_region.size / PAGE_SIZE) + 1, sizeof(struct page *), GFP_KERNEL);

			// First check if there already is a memory region which would overlap with the new one
			mmu_add_memory_region(g->mmu, current_memory_region);

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
