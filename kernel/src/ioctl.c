#include <ioctl.h>
#include <debug.h>
#include <mah_defs.h>
#include <guest.h>
#include <memory.h>
#include <svm.h>

#include <asm/pgtable.h>
#include <linux/slab.h> 
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

static long unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long argp) {
	int i;
	user_arg_registers 		regs;
	internal_vcpu*			vcpu;
	internal_vcpu*			current_vcpu;
	user_vcpu_exit			exit_reason;
	user_intercept_reasons		intercept_reasons;
	
	printk(DBG "Got ioctl cmd: 0x%x\n", cmd);
	
	switch (cmd) {
		case MAH_IOCTL_CREATE_GUEST:
			guest_lock_write();

			guest = (internal_guest*) kmalloc(sizeof(internal_guest), GFP_KERNEL);
			memset(guest, 0, sizeof(internal_guest));
			
			// Allocate a Page Global Directory as root for the nested pagetables.
			guest->nested_pagetables = kmalloc(PAGE_SIZE, GFP_KERNEL);
			TEST_PTR((uint64_t)guest->nested_pagetables, uint64_t, guest_unlock_write())

			memset(guest->nested_pagetables, 0, PAGE_SIZE);

			// SVM offers the possibility to intercept MSR instructions via a 
			// SVM MSR permissions map (MSR). Each MSR is covered by two bits,
			// the lsb controls read access and the msb controls write acccess.
			// The MSR bitmap consists of 4 bit vectors of 2kB each.
			// MSR bitmap offset        MSR range
			// 0x0      - 0x7FFF:        0x0        - 0x1FFF
			// 0x800    - 0xFFFF:        0xC0000000 - 0xC0001FFF
			// 0x1000   - 0x17FFF:       0xC0010000 - 0xC0011FFF
			// 0x1800   - 0x1FFFF:       Reserved
			guest->msr_permission_map = (uint8_t*) kmalloc(MSRPM_SIZE, GFP_KERNEL);
			TEST_PTR(guest->msr_permission_map, uint8_t*, guest_unlock_write())

			for(i = 0; i < MSRPM_SIZE; i++) guest->msr_permission_map[i] = 0;

			// We only allow direct access to a few selected MSRs.
			set_msrpm_permission(guest->msr_permission_map, MSR_STAR, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_LSTAR, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_CSTAR, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_SYSENTER_CS, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_SYSENTER_ESP, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_SYSENTER_EIP, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_GS_BASE, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_FS_BASE, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_KERNEL_GS_BASE, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_SYSCALL_MASK, 1, 1);
			/*set_msrpm_permission(guest->msr_permission_map, MSR_IA32_SPEC_CTRL, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_PRED_CMD, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_LASTBRANCHTOIP, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_LASTINTFROMIP, 1, 1);
			set_msrpm_permission(guest->msr_permission_map, MSR_IA32_LASTINTTOIP, 1, 1);*/

			guest_unlock_write();

			break;
			
		case MAH_IOCTL_CREATE_VCPU:
			guest_lock_write();

			TEST_PTR(guest, internal_guest*, guest_unlock_write())
			
			// Test if creating a VCPU exceedes the phyiscal cores on the system
			// TODO
			
			vcpu = kmalloc(sizeof(internal_vcpu), GFP_KERNEL);
			memset(vcpu, 0, sizeof(internal_vcpu));
			
			if (guest->vcpus == NULL) {
				guest->vcpus = vcpu;
				current_vcpu = vcpu;
			} else {
				current_vcpu = guest->vcpus;
				while (current_vcpu->next != NULL) {
					current_vcpu = current_vcpu->next;
				}
				current_vcpu->next = vcpu;
			}
			
			current_vcpu->physical_core = guest->used_cores;
			guest->used_cores++;
			
			current_vcpu->vcpu_vmcb = kmalloc(PAGE_SIZE, GFP_KERNEL);
			current_vcpu->host_vmcb = kmalloc(PAGE_SIZE, GFP_KERNEL);
			current_vcpu->vcpu_regs = kmalloc(sizeof(gp_regs), GFP_KERNEL);
			
			TEST_PTR(current_vcpu->vcpu_vmcb, vmcb*, guest_unlock_write());
			TEST_PTR(current_vcpu->host_vmcb, vmcb*, guest_unlock_write());
			TEST_PTR(current_vcpu->vcpu_regs, gp_regs*, guest_unlock_write());
			
			reset_vcpu(guest, current_vcpu);
			
			guest_unlock_write();

			break;
			
		case MAH_IOCTL_SET_REGISTERS:
			guest_lock_read();

			TEST_PTR(guest, internal_guest*, guest_unlock_read())
			TEST_PTR(guest->vcpus, internal_vcpu*, guest_unlock_read())
			TEST_PTR(argp, unsigned long, guest_unlock_read())

			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) return -EFAULT;
			
			current_vcpu = map_vcpu_id_to_vcpu(regs.vpcu_id, guest);
			
			TEST_PTR(current_vcpu, internal_vcpu*, guest_unlock_read());
			TEST_PTR(current_vcpu->vcpu_vmcb, vmcb*, guest_unlock_read());
			TEST_PTR(current_vcpu->vcpu_regs, gp_regs*, guest_unlock_read());
			
			current_vcpu->vcpu_vmcb->rax = regs.rax;
			current_vcpu->vcpu_vmcb->rsp = regs.rsp;
			current_vcpu->vcpu_vmcb->rip = regs.rip;
			
			current_vcpu->vcpu_vmcb->cr0 = regs.cr0;
			current_vcpu->vcpu_vmcb->cr2 = regs.cr2;
			current_vcpu->vcpu_vmcb->cr3 = regs.cr3;
			current_vcpu->vcpu_vmcb->cr4 = regs.cr4;
			
			current_vcpu->vcpu_vmcb->efer   = regs.efer;
			current_vcpu->vcpu_vmcb->star   = regs.star;
			current_vcpu->vcpu_vmcb->lstar  = regs.lstar;
			current_vcpu->vcpu_vmcb->cstar  = regs.cstar;
			current_vcpu->vcpu_vmcb->sfmask = regs.sfmask;
			current_vcpu->vcpu_vmcb->kernel_gs_base = regs.kernel_gs_base;
			current_vcpu->vcpu_vmcb->sysenter_cs    = regs.sysenter_cs;
			current_vcpu->vcpu_vmcb->sysenter_esp   = regs.sysenter_esp;
			current_vcpu->vcpu_vmcb->sysenter_eip   = regs.sysenter_eip;
			
			current_vcpu->vcpu_regs->rbx = regs.rbx;
			current_vcpu->vcpu_regs->rcx = regs.rcx;
			current_vcpu->vcpu_regs->rdx = regs.rdx;
			current_vcpu->vcpu_regs->rdi = regs.rdi;
			current_vcpu->vcpu_regs->rsi = regs.rsi;
			current_vcpu->vcpu_regs->r8  = regs.r8;
			current_vcpu->vcpu_regs->r9  = regs.r9;
			current_vcpu->vcpu_regs->r10 = regs.r10;
			current_vcpu->vcpu_regs->r11 = regs.r11;
			current_vcpu->vcpu_regs->r12 = regs.r12;
			current_vcpu->vcpu_regs->r13 = regs.r13;
			current_vcpu->vcpu_regs->r14 = regs.r14;
			current_vcpu->vcpu_regs->r15 = regs.r15;
			current_vcpu->vcpu_regs->rbp = regs.rbp;
			
			memcpy(&current_vcpu->vcpu_vmcb->es, &regs.es, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->cs, &regs.cs, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->ss, &regs.ss, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->ds, &regs.ds, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->fs, &regs.fs, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->gs, &regs.gs, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->gdtr, &regs.gdtr, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->ldtr, &regs.ldtr, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->idtr, &regs.idtr, sizeof(segment));
			memcpy(&current_vcpu->vcpu_vmcb->tr, &regs.tr, sizeof(segment));

			guest_unlock_read();
			
			break;
			
		case MAH_IOCTL_GET_REGISTERS:
			guest_lock_read();

			TEST_PTR(guest, internal_guest*, guest_unlock_read())
			TEST_PTR(guest->vcpus, internal_vcpu*, guest_unlock_read())
			TEST_PTR(argp, unsigned long, guest_unlock_read())
			
			if (copy_from_user((void*)&regs, (void __user *)argp, sizeof(user_arg_registers))) return -EFAULT;
			
			current_vcpu = map_vcpu_id_to_vcpu(regs.vpcu_id, guest);
			
			TEST_PTR(current_vcpu, internal_vcpu*, guest_unlock_read());
			TEST_PTR(current_vcpu->vcpu_vmcb, vmcb*, guest_unlock_read());
			TEST_PTR(current_vcpu->vcpu_regs, gp_regs*, guest_unlock_read());
			
			regs.rax = current_vcpu->vcpu_vmcb->rax;
			regs.rsp = current_vcpu->vcpu_vmcb->rsp;
			regs.rip = current_vcpu->vcpu_vmcb->rip;
			
			regs.cr0 = current_vcpu->vcpu_vmcb->cr0;
			regs.cr2 = current_vcpu->vcpu_vmcb->cr2;
			regs.cr3 = current_vcpu->vcpu_vmcb->cr3;
			regs.cr4 = current_vcpu->vcpu_vmcb->cr4;
			
			regs.efer   = current_vcpu->vcpu_vmcb->efer;
			regs.star   = current_vcpu->vcpu_vmcb->star;
			regs.lstar  = current_vcpu->vcpu_vmcb->lstar;
			regs.cstar  = current_vcpu->vcpu_vmcb->cstar;
			regs.sfmask = current_vcpu->vcpu_vmcb->sfmask;
			regs.kernel_gs_base = current_vcpu->vcpu_vmcb->kernel_gs_base;
			regs.sysenter_cs    = current_vcpu->vcpu_vmcb->sysenter_cs;
			regs.sysenter_esp   = current_vcpu->vcpu_vmcb->sysenter_esp;
			regs.sysenter_eip   = current_vcpu->vcpu_vmcb->sysenter_eip;
			
			regs.rbx = current_vcpu->vcpu_regs->rbx;
			regs.rcx = current_vcpu->vcpu_regs->rcx;
			regs.rdx = current_vcpu->vcpu_regs->rdx;
			regs.rdi = current_vcpu->vcpu_regs->rdi;
			regs.rsi = current_vcpu->vcpu_regs->rsi;
			regs.r8  = current_vcpu->vcpu_regs->r8;
			regs.r9  = current_vcpu->vcpu_regs->r9;
			regs.r10 = current_vcpu->vcpu_regs->r10;
			regs.r11 = current_vcpu->vcpu_regs->r11;
			regs.r12 = current_vcpu->vcpu_regs->r12;
			regs.r13 = current_vcpu->vcpu_regs->r13;
			regs.r14 = current_vcpu->vcpu_regs->r14;
			regs.r15 = current_vcpu->vcpu_regs->r15;
			regs.rbp = current_vcpu->vcpu_regs->rbp;
			
			memcpy(&regs.es, &current_vcpu->vcpu_vmcb->es, sizeof(segment));
			memcpy(&regs.cs, &current_vcpu->vcpu_vmcb->cs, sizeof(segment));
			memcpy(&regs.ss, &current_vcpu->vcpu_vmcb->ss, sizeof(segment));
			memcpy(&regs.ds, &current_vcpu->vcpu_vmcb->ds, sizeof(segment));
			memcpy(&regs.fs, &current_vcpu->vcpu_vmcb->fs, sizeof(segment));
			memcpy(&regs.gs, &current_vcpu->vcpu_vmcb->gs, sizeof(segment));
			memcpy(&regs.gdtr, &current_vcpu->vcpu_vmcb->gdtr, sizeof(segment));
			memcpy(&regs.ldtr, &current_vcpu->vcpu_vmcb->ldtr, sizeof(segment));
			memcpy(&regs.idtr, &current_vcpu->vcpu_vmcb->idtr, sizeof(segment));
			memcpy(&regs.tr, &current_vcpu->vcpu_vmcb->tr, sizeof(segment));
			
			if (copy_to_user((void __user *)argp, (void*)&regs, sizeof(user_arg_registers))) {
				guest_unlock_read();
				return -EFAULT;
			}

			guest_unlock_read();
			
			break;
			
		case MAH_IOCTL_VCPU_RUN:
			guest_lock_read();

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

			guest_unlock_read();
			
			break;
		
		case MAH_IOCTL_DESTROY_GUEST:
			guest_lock_write();
			
			guest = NULL;
			
			guest_unlock_write();
			
			break;
			
		case MAH_SET_INTERCEPT_REASONS:
			guest_lock_write();

			TEST_PTR(guest, internal_guest*, guest_unlock_write());
			TEST_PTR(guest->vcpus, internal_vcpu*, guest_unlock_write());
			TEST_PTR(argp, unsigned long, guest_unlock_write());
			TEST_PTR(guest->vcpus->vcpu_vmcb, vmcb*, guest_unlock_write());
			TEST_PTR(guest->vcpus->host_vmcb, vmcb*, guest_unlock_write());
			
			if (copy_from_user((void*)&intercept_reasons, (void __user *)argp, sizeof(user_intercept_reasons))) return -EFAULT;
			
			// Update all VMCBs of all VPCUs for the guest.
			guest->intercept_exceptions = intercept_reasons.intercept_exceptions;
			guest->intercept = intercept_reasons.intercept;
			
			update_intercept_reasons(guest);

			guest_unlock_write();
			
			break;
			
		default:
			printk(DBG "ioctl command not supported: 0x%x\n", cmd);
			return -EINVAL;
	}
	
	return 0;
}

// Memory for the guest will be allocated via mmap()
static int proc_ctl_mmap(struct file *file, struct vm_area_struct *vma) {
	unsigned long donated_memory;
	unsigned long start;
	unsigned long address;
	unsigned long pfn;
	unsigned long length;
	int i;
	
	start = vma->vm_start;
	length = vma->vm_end - vma->vm_start;
	donated_memory = (unsigned long)vmalloc(length);
	address = donated_memory;
	i = 0;
	
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	
	while (length > 0) {
		pfn = vmalloc_to_pfn((void*)address);
				
		if (remap_pfn_range(vma,
				    start,
				    pfn,
				    PAGE_SIZE,
				    vma->vm_page_prot)) {
			printk(DBG "remap_pfn_range failed\n");
			return -EAGAIN;
		}
		
		if (map_to(guest, guest->highest_phys_addr + i * PAGE_SIZE, pfn << 12, PAGE_SIZE) == ERROR) {
			printk(DBG "Adding mapping of donated memory failed.\n");
			return ERROR;
		}
		
		start += PAGE_SIZE;
		address += PAGE_SIZE;
		length  -= PAGE_SIZE;
		i++;
	}
	
	guest->highest_phys_addr += vma->vm_end - vma->vm_start;
	
	return 0;
}

static struct file_operations proc_ctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = unlocked_ioctl,
	.mmap = proc_ctl_mmap
};

void init_ctl_interface(){
    proc_create(PROC_PATH, 0, NULL, &proc_ctl_fops);
}

void finit_ctl_interface(){
    remove_proc_entry(PROC_PATH, NULL);
}
