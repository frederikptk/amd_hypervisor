#include <svm.h>
#include <ioctl.h>
#include <debug.h>
#include <memory.h>

#include <linux/init.h>
#include <linux/module.h>
#include <asm/msr-index.h>
#include <asm/msr.h>

MODULE_LICENSE("GPL");

u64 msr_rdmsr(u32 msr) {
	u32 a, d;
	__asm__ __volatile__("rdmsr" : "=a"(a), "=d"(d) : "c"(msr) : "memory");
	return a | ((u64) d << 32);
}

int reset_vcpu(internal_guest* g, internal_vcpu* vcpu) {
	TEST_PTR(g, internal_guest*,)
	TEST_PTR(vcpu, internal_vcpu*,)
	TEST_PTR(vcpu->vcpu_vmcb, vmcb*,)
	
	vcpu->vcpu_vmcb->guest_asid = 1;

	vcpu->vcpu_vmcb->cs.selector = 0xf000;
	vcpu->vcpu_vmcb->cs.base = 0x0;
	vcpu->vcpu_vmcb->cs.limit = 0xffffffff;
	vcpu->vcpu_vmcb->cs.attrib = 0x049b;
	vcpu->vcpu_vmcb->ds.limit = 0xffffffff;
	vcpu->vcpu_vmcb->ds.attrib = 0x0093;
	vcpu->vcpu_vmcb->es.limit = 0xffffffff;
	vcpu->vcpu_vmcb->es.attrib = 0x0093;
	vcpu->vcpu_vmcb->fs.limit = 0xffffffff;
	vcpu->vcpu_vmcb->fs.attrib = 0x0093;
	vcpu->vcpu_vmcb->gs.limit = 0xffffffff;
	vcpu->vcpu_vmcb->gs.attrib = 0x0093;
	vcpu->vcpu_vmcb->ss.limit = 0xffffffff;
	vcpu->vcpu_vmcb->ss.attrib = 0x0093;

	vcpu->vcpu_vmcb->cr0 = X86_CR0_ET | X86_CR0_PE;
	vcpu->vcpu_vmcb->cr3 = 0;
	vcpu->vcpu_vmcb->cr4 = 0;

	vcpu->vcpu_vmcb->rflags = 0x02;

	vcpu->vcpu_vmcb->gdtr.limit = 0xffff;
	vcpu->vcpu_vmcb->idtr.limit = 0xffff;

	vcpu->vcpu_vmcb->dr6 = 0xffff0ff0;

	vcpu->vcpu_vmcb->efer = EFER_SVME;
	
	// Enable nested paging
	vcpu->vcpu_vmcb->nested_and_sec_control |= 1;
	
	// Set the nested pagetables
	vcpu->vcpu_vmcb->n_cr3 = __pa(g->nested_pagetables);

	// Intercept all possible exceptions and instructions
	vcpu->vcpu_vmcb->intercept_exceptions = 0xffffffff;
	vcpu->vcpu_vmcb->intercept = 0xffffffffffffffff;

	vcpu->vcpu_vmcb->msrprm_base_pa = __pa(g->msr_permission_map);
	
	vcpu->state = VCPU_STATE_CREATED;

	vcpu->vcpu_vmcb->vmcb_clean = 0x0;
	
	return SUCCESS;
}

void handle_vmexit(internal_vcpu* current_vcpu) {
	uint64_t 					efer;
	internal_memory_region* 	current_memory_region_it;
	struct list_head*			list_it;
	
	asm volatile ("stgi");
	
	efer = msr_rdmsr(MSR_EFER);
	wrmsrl_safe(MSR_EFER, efer & ~EFER_SVME);

	// Check if we need to swap in userspace memory
	if (current_vcpu->vcpu_vmcb->exitcode == VMEXIT_NPF) {
		if (guest->memory_regions != NULL) {
			list_for_each(list_it, &guest->memory_regions->list) {
				current_memory_region_it = list_entry(list_it, internal_memory_region, list);

				// First, check if an MMIO region was accessed
				if (current_memory_region_it->is_mmio == 1) {
					// TODO: handle
				} else {
					// Check if the fault was during the nested pagetablewalk and if the nested page was not present.
					if ((current_vcpu->vcpu_vmcb->exitinfo1 & (uint64_t)1) == 0 && (current_vcpu->vcpu_vmcb->exitinfo1 & ((uint64_t)1 >> 33)) != 0) {
						if ((current_memory_region_it->guest_addr <= current_vcpu->vcpu_vmcb->exitinfo2) &&
								(current_memory_region_it->guest_addr + current_memory_region_it->size >= current_vcpu->vcpu_vmcb->exitinfo2)) {
							// TODO: swap in
							current_memory_region_it->is_present = 1;
						}
					}
				}
			}
		}
	}
	
	printk(DBG "handle_vmexit\n");
}

void run_guest(internal_guest* g) {
	internal_vcpu* current_vcpu = NULL;

	while (current_vcpu != NULL) {
		run_vcpu(current_vcpu);
		current_vcpu = current_vcpu->next;
	}
}

void run_vcpu_internal(void* info) {
	uint64_t efer;
	uint64_t vm_hsave_pa;
	uint64_t host_fs_base, host_gs_base;
	internal_vcpu* vcpu = (internal_vcpu*) info;
	
	if (vcpu == NULL) return;
	if (vcpu->vcpu_vmcb == NULL || vcpu->host_vmcb == NULL || vcpu->vcpu_regs == NULL) return;
	
	if (get_cpu() == vcpu->physical_core) {
		printk(DBG "Running on CPU: %d\n", smp_processor_id());
		
		if ((msr_rdmsr(MSR_EFER) & EFER_SVME) != 0) {
			vcpu->state = VCPU_STATE_FAILED;
			return;
		}
		
		vcpu->state = VCPU_STATE_RUNNING;
		
		vm_hsave_pa = __pa(vcpu->host_vmcb);
		wrmsrl_safe(MSR_VM_HSAVE_PA, vm_hsave_pa);
		
		efer = msr_rdmsr(MSR_EFER);
		wrmsrl_safe(MSR_EFER, efer | EFER_SVME);

		host_fs_base = msr_rdmsr(MSR_FS_BASE);
		host_gs_base = msr_rdmsr(MSR_GS_BASE);

		run_vcpu_asm(__pa(vcpu->vcpu_vmcb), __pa(vcpu->host_vmcb), (unsigned long)(vcpu->vcpu_regs));
		handle_vmexit(vcpu);

		wrmsrl_safe(MSR_FS_BASE, host_fs_base);
		wrmsrl_safe(MSR_GS_BASE, host_gs_base);
		
		vcpu->state = VCPU_STATE_PAUSED;
	}
	put_cpu();
}

user_vcpu_exit run_vcpu(internal_vcpu* vcpu) {
	user_vcpu_exit ret;
	
	if (vcpu != NULL) {
		on_each_cpu((void*)run_vcpu_internal, vcpu, 1);
	
		ret.exitcode = vcpu->vcpu_vmcb->exitcode;
		ret.exitinfo1 = vcpu->vcpu_vmcb->exitinfo1;
		ret.exitinfo2 = vcpu->vcpu_vmcb->exitinfo2;
	} else {
		ret.exitcode = 0;
		ret.exitinfo1 = 0;
		ret.exitinfo2 = 0;
	}
	
	return ret;
}

int test_svm_support(void) { 
	unsigned int cpuid_ret_val;
	__asm__ ("cpuid; movl %%ecx, %0;" : "=r"(cpuid_ret_val));
	if (cpuid_ret_val && 0x80000001 == 0){
		printk(KERN_INFO "[AMD_SVM]: AMD SVM not supported\n");
		return ERROR;
	}

	__asm__ ("cpuid; movl %%edx, %0;" : "=r"(cpuid_ret_val));
	if (cpuid_ret_val && 0x8000000A == 0){
		printk(KERN_INFO "[AMD_SVM]: AMD SVM disabled at bios\n");
		return ERROR;
	}

	return SUCCESS;
}

int set_msrpm_permission(uint8_t* msr_permission_map, uint32_t msr, int read, int write) {
	unsigned int idx; // the index in the table
	unsigned int offset; // the offset of the msr in a single byte

	if (read != 0 || read != 1) return ERROR;
	if (write != 0 || write != 1) return ERROR;

	idx = (int)(msr / 4);
	offset = 2 * (msr & 0xf);

	msr_permission_map[idx] = msr_permission_map[idx] & ~(0b11 << offset);

	msr_permission_map[idx] = msr_permission_map[idx] | (read << offset);
	msr_permission_map[idx] = msr_permission_map[idx] | (write << (offset + 2));

	return SUCCESS;
}

static int __init mah_init(void) {
	printk(DBG "Loaded MAH kernel module\n");
	init_ctl_interface();
	return 0;
}

static void __exit mah_exit(void) {
	printk(DBG "Unloaded MAH kernel module\n");
	finit_ctl_interface();
}

module_init(mah_init);
module_exit(mah_exit);
