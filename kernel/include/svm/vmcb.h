/*
 * This file contains basic definitions of datastructures and types used by AMD SVM.
 */

#pragma once

#include <linux/types.h>

// structure to represent x86 segment registers
struct __attribute__ ((__packed__)) segment {
	uint16_t	selector;
	uint16_t	attrib;
	uint32_t	limit;
	uint64_t	base;
} typedef segment;

// general VMCB structure (like in KVM)
struct __attribute__ ((__packed__)) vmcb{
	// Control area
	uint32_t 	intercept_cr;
	uint32_t 	intercept_dr;
	uint32_t 	intercept_exceptions;
	uint64_t 	intercept; // various intercepts for different kinds of instructions
	uint8_t 	reserved_1[40];
	uint16_t	pause_filter_threshold;
	uint16_t	pause_filter_count;
	uint64_t	iopm_base_pa;
	uint64_t	msrprm_base_pa;
	uint64_t	tsc_offset;
	uint32_t	guest_asid;
	uint8_t		tlb_control;
	uint8_t		reserved_2[3];
	uint32_t	interrupt_control;
	uint32_t	interrupt_vector;
	uint32_t	interrupt_state;
	uint8_t		reserved_3[4];
	uint64_t	exitcode;
	uint64_t	exitinfo1;
	uint64_t	exitinfo2;
	uint64_t	exitintinfo;
	uint64_t	nested_and_sec_control;
	uint64_t	avic_apic_bar;
	uint64_t	ghcb_address;
	uint32_t 	event_inject;
	uint32_t 	event_inject_error;
	uint64_t 	n_cr3;
	uint64_t 	virt_ext;
	uint32_t 	vmcb_clean;
	uint8_t 	reserved_5[4];
	uint64_t 	next_rip;
	uint8_t 	insn_len;
	uint8_t 	insn_bytes[15];
	uint64_t 	avic_backing_page;
	uint8_t 	reserved_6[8];
	uint64_t	avic_logical_id;
	uint64_t 	avic_physical_id;
	uint8_t 	reserved_7[768];

	// Save area
	struct segment	es;
	struct segment	cs;
	struct segment	ss;
	struct segment	ds;
	struct segment	fs;
	struct segment	gs;
	struct segment	gdtr;
	struct segment	ldtr;
	struct segment	idtr;
	struct segment	tr;
	uint8_t 	reserved_8[43];
	uint8_t 	cpl;
	uint8_t		reserved_9[4];
	uint64_t	efer;
	uint8_t		reserved_10[112];
	uint64_t	cr4;
	uint64_t	cr3;
	uint64_t	cr0;
	uint64_t	dr7;
	uint64_t	dr6;
	uint64_t	rflags;
	uint64_t	rip;
	uint8_t		reserved_11[88];
	uint64_t	rsp;
	uint8_t		reserved_12[24];
	uint64_t	rax;
	uint64_t	star;
	uint64_t	lstar;
	uint64_t	cstar;
	uint64_t	sfmask;
	uint64_t	kernel_gs_base;
	uint64_t	sysenter_cs;
	uint64_t	sysenter_esp;
	uint64_t	sysenter_eip;
	uint64_t	cr2;
	uint8_t		reserved_13[32];
	uint64_t	gpat;
	uint64_t	dbgctl;
	uint64_t	br_from;
	uint64_t	br_to;
	uint64_t	last_excp_from;
	uint64_t	last_excp_to;
} typedef vmcb;
_Static_assert (sizeof(vmcb) == 0x698, "vmcb struct size false");

// a struct representing the guest general purpose register state: these
// will not be stored in the VMCB
struct __attribute__ ((__packed__)) gp_regs {
	uint64_t 	rbx;
	uint64_t 	rcx;
	uint64_t 	rdx;
	uint64_t 	rdi;
	uint64_t 	rsi;
	uint64_t 	r8;
	uint64_t 	r9;
	uint64_t 	r10;
	uint64_t 	r11;
	uint64_t 	r12;
	uint64_t 	r13;
	uint64_t 	r14;
	uint64_t 	r15;
	uint64_t 	rbp;
	uint64_t	xmm0 [2];
	uint64_t	xmm1 [2];
	uint64_t	xmm2 [2];
	uint64_t	xmm3 [2];
	uint64_t	xmm4 [2];
	uint64_t	xmm5 [2];
	uint64_t	xmm6 [2];
	uint64_t	xmm7 [2];
	uint64_t	xmm8 [2];
	uint64_t	xmm9 [2];
	uint64_t	xmm10[2];
	uint64_t	xmm11[2];
	uint64_t	xmm12[2];
	uint64_t	xmm13[2];
	uint64_t	xmm14[2];
	uint64_t	xmm15[2];
} typedef gp_regs;

// Intercept related
#define INTERCEPT_MSR_PROT		(28 + 32) << 1
#define INTERCEPT_HLT			((uint64_t)1 << 24)
#define INTERCEPT_VMRUN			((uint64_t)1 << 32)

// MSR intercept
#define MSRPM_SIZE			0x1000 * 4

// Intercept exit codes
#define VMEXIT_MSR 		0x7c
#define VMEXIT_HLT		0x78
#define VMEXIT_VMRUN 	0x80
#define VMEXIT_NPF		0x400

// NPF exitcodes
#define NPF_IN_VMM_PAGE			(uint64_t)1 << 33
#define NPF_IN_GUEST_PAGE		(uint64_t)1 << 32
// TODO
#define NPF_USER_ACCESS			(uint64_t)1 << 0
#define NPF_WRITE_ACCESS		(uint64_t)1 << 0
#define NPF_CODE_ACCESS			(uint64_t)1 << 0
#define NPF_NOT_PRESENT			(uint64_t)1 << 0