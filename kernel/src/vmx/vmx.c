#include <vmx/vmx.h>

inline vmx_internal_guest* to_vmx_guest(internal_guest *g) {
	return (vmx_internal_guest*)(g->arch_internal_guest);
}

inline vmx_internal_vcpu* to_svm_vcpu(internal_vcpu *vcpu) {
	return (vmx_internal_vcpu*)(vcpu->arch_internal_vcpu);
}

int vmx_reset_vcpu(vmx_internal_vcpu *vmx_vcpu) {
    uint32_t msr_vmx_basic;

    msr_vmx_basic = msr_rdmsr(MSR_FS_BASE);

    // Initialize the vmxon region
    vmx_vcpu->vmxon_region->vmcs_revision_identifier = msr_vmx_basic;

    // Initialize the vmcs region
    vmx_vcpu->vmcs_region->header.vmcs_revision_identifier = msr_vmx_basic;
    vmx_vcpu->vmcs_region->header.shadow_vmcs_indicator = 0;

    return 0;
}

void vmx_handle_vm_exit() {

}

void enable_vmx() {

}

void disable_vmx() {

}

void vmx_run_vcpu() {

}