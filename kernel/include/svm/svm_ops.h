#pragma once

#include <memory.h>
#include <guest.h>
#include <hyperkraken_defs.h>

#include <stddef.h>
#include <linux/list.h>

void* 	svm_create_arch_internal_vcpu(internal_guest* g);
int 	svm_destroy_arch_internal_vcpu(internal_vcpu* vcpu);
void* 	svm_create_internal_guest(void);
void 	svm_destroy_internal_guest(internal_guest* g);
void 	svm_set_vcpu_registers(internal_vcpu* vcpu, user_arg_registers* regs);
void 	svm_get_vcpu_registers(internal_vcpu* vcpu, user_arg_registers* regs);
void 	svm_set_memory_region(internal_guest* g, internal_memory_region* memory_region);
int     svm_handle_breakpoint(internal_guest *g, internal_vcpu *vcpu);

void	init_svm_hyperkraken_ops(void);