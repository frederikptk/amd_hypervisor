#pragma once

#include <guest.h>
#include <mah_defs.h>

void handle_vmexit(internal_vcpu* current_vcpu);
void run_guest(internal_guest* g);
user_vcpu_exit run_vcpu(internal_vcpu* vcpu);
int reset_vcpu(internal_guest* g, internal_vcpu* vcpu);
int test_svm_support(void);

extern void run_vcpu_asm(unsigned long phys_addr_guest_vmcb, unsigned long phys_addr_host_vmcb, unsigned long saved_guest_regs_addr, internal_vcpu* vcpu);
