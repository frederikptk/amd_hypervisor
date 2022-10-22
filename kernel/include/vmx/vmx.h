#pragma once

#include <linux/types.h>

struct __attribute__ ((__packed__)) internal_vmcs  typedef internal_vmcs;
struct __attribute__ ((__packed__)) internal_vmxon typedef internal_vmxon;

struct vmx_internal_vcpu {
	internal_vmcs*	vmcs_region;
	internal_vmxon*	vmxon_region;
	gp_regs*		vcpu_regs;
    void*           vmm_stack;
} typedef vmx_internal_vcpu;

struct vmx_internal_guest {
	uint64_t		highest_phys_addr; // contains the number of bytes the guest has available as memory
	uint64_t		used_cores;
	
	void*			nested_pagetables; // map guest physical to host physical memory
} typedef vmx_internal_guest;

inline vmx_internal_guest* to_vmx_guest(internal_guest *g);
inline vmx_internal_vcpu* to_svm_vcpu(internal_vcpu *vcpu);

struct __attribute__ ((__packed__)) internal_vmcs {
    struct {
        uint32_t vmcs_revision_identifier : 31;
        uint32_t shadow_vmcs_indicator : 1;
    } header;

    uint32_t vmx_abort_indicator;
    uint8_t vmcs_data[0x1000 - 2 * sizeof(unit32_t)];
} typedef internal_vmcs;

struct __attribute__ ((__packed__)) internal_vmxon {
    uint32_t vmcs_revision_identifier;
    uint8_t vmcs_data[0x1000 - sizeof(unit32_t)];
} typedef internal_vmxon;

enum vmcs_field_offsets {
    GUEST_ES_SELECTOR             = 0x0800,
    GUEST_CS_SELECTOR             = 0x0802,
    GUEST_SS_SELECTOR             = 0x0804,
    GUEST_DS_SELECTOR             = 0x0806,
    GUEST_FS_SELECTOR             = 0x0808,
    GUEST_GS_SELECTOR             = 0x080a,
    GUEST_LDTR_SELECTOR           = 0x080c,
    GUEST_TR_SELECTOR             = 0x080e,
    HOST_ES_SELECTOR              = 0x0c00,
    HOST_CS_SELECTOR              = 0x0c02,
    HOST_SS_SELECTOR              = 0x0c04,
    HOST_DS_SELECTOR              = 0x0c06,
    HOST_FS_SELECTOR              = 0x0c08,
    HOST_GS_SELECTOR              = 0x0c0a,
    HOST_TR_SELECTOR              = 0x0c0c,
    IO_BITMAP_A                   = 0x2000,
    IO_BITMAP_A_HIGH              = 0x2001,
    IO_BITMAP_B                   = 0x2002,
    IO_BITMAP_B_HIGH              = 0x2003,
    MSR_BITMAP                    = 0x2004,
    MSR_BITMAP_HIGH               = 0x2005,
    VM_EXIT_MSR_STORE_ADDR        = 0x2006,
    VM_EXIT_MSR_STORE_ADDR_HIGH   = 0x2007,
    VM_EXIT_MSR_LOAD_ADDR         = 0x2008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH    = 0x2009,
    VM_ENTRY_MSR_LOAD_ADDR        = 0x200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH   = 0x200b,
    TSC_OFFSET                    = 0x2010,
    TSC_OFFSET_HIGH               = 0x2011,
    VIRTUAL_APIC_PAGE_ADDR        = 0x2012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH   = 0x2013,
    VMFUNC_CONTROLS               = 0x2018,
    VMFUNC_CONTROLS_HIGH          = 0x2019,
    EPT_POINTER                   = 0x201A,
    EPT_POINTER_HIGH              = 0x201B,
    EPTP_LIST                     = 0x2024,
    EPTP_LIST_HIGH                = 0x2025,
    GUEST_PHYSICAL_ADDRESS        = 0x2400,
    GUEST_PHYSICAL_ADDRESS_HIGH   = 0x2401,
    VMCS_LINK_POINTER             = 0x2800,
    VMCS_LINK_POINTER_HIGH        = 0x2801,
    GUEST_IA32_DEBUGCTL           = 0x2802,
    GUEST_IA32_DEBUGCTL_HIGH      = 0x2803,
    PIN_BASED_VM_EXEC_CONTROL     = 0x4000,
    CPU_BASED_VM_EXEC_CONTROL     = 0x4002,
    EXCEPTION_BITMAP              = 0x4004,
    PAGE_FAULT_ERROR_CODE_MASK    = 0x4006,
    PAGE_FAULT_ERROR_CODE_MATCH   = 0x4008,
    CR3_TARGET_COUNT              = 0x400a,
    VM_EXIT_CONTROLS              = 0x400c,
    VM_EXIT_MSR_STORE_COUNT       = 0x400e,
    VM_EXIT_MSR_LOAD_COUNT        = 0x4010,
    VM_ENTRY_CONTROLS             = 0x4012,
    VM_ENTRY_MSR_LOAD_COUNT       = 0x4014,
    VM_ENTRY_INTR_INFO_FIELD      = 0x4016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x4018,
    VM_ENTRY_INSTRUCTION_LEN      = 0x401a,
    TPR_THRESHOLD                 = 0x401c,
    SECONDARY_VM_EXEC_CONTROL     = 0x401e,
    VM_INSTRUCTION_ERROR          = 0x4400,
    VM_EXIT_REASON                = 0x4402,
    VM_EXIT_INTR_INFO             = 0x4404,
    VM_EXIT_INTR_ERROR_CODE       = 0x4406,
    IDT_VECTORING_INFO_FIELD      = 0x4408,
    IDT_VECTORING_ERROR_CODE      = 0x440a,
    VM_EXIT_INSTRUCTION_LEN       = 0x440c,
    VMX_INSTRUCTION_INFO          = 0x440e,
    GUEST_ES_LIMIT                = 0x4800,
    GUEST_CS_LIMIT                = 0x4802,
    GUEST_SS_LIMIT                = 0x4804,
    GUEST_DS_LIMIT                = 0x4806,
    GUEST_FS_LIMIT                = 0x4808,
    GUEST_GS_LIMIT                = 0x480a,
    GUEST_LDTR_LIMIT              = 0x480c,
    GUEST_TR_LIMIT                = 0x480e,
    GUEST_GDTR_LIMIT              = 0x4810,
    GUEST_IDTR_LIMIT              = 0x4812,
    GUEST_ES_AR_BYTES             = 0x4814,
    GUEST_CS_AR_BYTES             = 0x4816,
    GUEST_SS_AR_BYTES             = 0x4818,
    GUEST_DS_AR_BYTES             = 0x481a,
    GUEST_FS_AR_BYTES             = 0x481c,
    GUEST_GS_AR_BYTES             = 0x481e,
    GUEST_LDTR_AR_BYTES           = 0x4820,
    GUEST_TR_AR_BYTES             = 0x4822,
    GUEST_INTERRUPTIBILITY_INFO   = 0x4824,
    GUEST_ACTIVITY_STATE          = 0x4826,
    GUEST_SM_BASE                 = 0x4828,
    GUEST_SYSENTER_CS             = 0x482A,
    HOST_IA32_SYSENTER_CS         = 0x4c00,
    CR0_GUEST_HOST_MASK           = 0x6000,
    CR4_GUEST_HOST_MASK           = 0x6002,
    CR0_READ_SHADOW               = 0x6004,
    CR4_READ_SHADOW               = 0x6006,
    CR3_TARGET_VALUE0             = 0x6008,
    CR3_TARGET_VALUE1             = 0x600a,
    CR3_TARGET_VALUE2             = 0x600c,
    CR3_TARGET_VALUE3             = 0x600e,
    EXIT_QUALIFICATION            = 0x6400,
    GUEST_LINEAR_ADDRESS          = 0x640a,
    GUEST_CR0                     = 0x6800,
    GUEST_CR3                     = 0x6802,
    GUEST_CR4                     = 0x6804,
    GUEST_ES_BASE                 = 0x6806,
    GUEST_CS_BASE                 = 0x6808,
    GUEST_SS_BASE                 = 0x680a,
    GUEST_DS_BASE                 = 0x680c,
    GUEST_FS_BASE                 = 0x680e,
    GUEST_GS_BASE                 = 0x6810,
    GUEST_LDTR_BASE               = 0x6812,
    GUEST_TR_BASE                 = 0x6814,
    GUEST_GDTR_BASE               = 0x6816,
    GUEST_IDTR_BASE               = 0x6818,
    GUEST_DR7                     = 0x681a,
    GUEST_RSP                     = 0x681c,
    GUEST_RIP                     = 0x681e,
    GUEST_RFLAGS                  = 0x6820,
    GUEST_PENDING_DBG_EXCEPTIONS  = 0x6822,
    GUEST_SYSENTER_ESP            = 0x6824,
    GUEST_SYSENTER_EIP            = 0x6826,
    HOST_CR0                      = 0x6c00,
    HOST_CR3                      = 0x6c02,
    HOST_CR4                      = 0x6c04,
    HOST_FS_BASE                  = 0x6c06,
    HOST_GS_BASE                  = 0x6c08,
    HOST_TR_BASE                  = 0x6c0a,
    HOST_GDTR_BASE                = 0x6c0c,
    HOST_IDTR_BASE                = 0x6c0e,
    HOST_IA32_SYSENTER_ESP        = 0x6c10,
    HOST_IA32_SYSENTER_EIP        = 0x6c12,
    HOST_RSP                      = 0x6c14,
    HOST_RIP                      = 0x6c16
};

// VM exit reasons
#define VM_EXIT_REASON_EXCEPTION_NMI                0x00
#define VM_EXIT_REASON_EXTERNAL_INTERRUPT           0x01
#define VM_EXIT_REASON_TRIPLE_FAULT                 0x02
#define VM_EXIT_REASON_INIT                         0x03
#define VM_EXIT_REASON_SIPI                         0x04
#define VM_EXIT_REASON_IO_SMI                       0x05
#define VM_EXIT_REASON_OTHER_SMI                    0x06
#define VM_EXIT_REASON_PENDING_VIRT_INTR            0x07
#define VM_EXIT_REASON_PENDING_VIRT_NMI             0x08
#define VM_EXIT_REASON_TASK_SWITCH                  0x09
#define VM_EXIT_REASON_CPUID                        0x0a
#define VM_EXIT_REASON_GETSEC                       0x0b
#define VM_EXIT_REASON_HLT                          0x0c
#define VM_EXIT_REASON_INVD                         0x0d
#define VM_EXIT_REASON_INVLPG                       0x0e
#define VM_EXIT_REASON_RDPMC                        0x0f
#define VM_EXIT_REASON_RDTSC                        0x10
#define VM_EXIT_REASON_RSM                          0x11
#define VM_EXIT_REASON_VMCALL                       0x12
#define VM_EXIT_REASON_VMCLEAR                      0x13
#define VM_EXIT_REASON_VMLAUNCH                     0x14
#define VM_EXIT_REASON_VMPTRLD                      0x15
#define VM_EXIT_REASON_VMPTRST                      0x16
#define VM_EXIT_REASON_VMREAD                       0x17
#define VM_EXIT_REASON_VMRESUME                     0x18
#define VM_EXIT_REASON_VMWRITE                      0x19
#define VM_EXIT_REASON_VMXOFF                       0x1a
#define VM_EXIT_REASON_VMXON                        0x1b
#define VM_EXIT_REASON_CR_ACCESS                    0x1c
#define VM_EXIT_REASON_DR_ACCESS                    0x1d
#define VM_EXIT_REASON_IO_INSTRUCTION               0x1e
#define VM_EXIT_REASON_MSR_READ                     0x1f
#define VM_EXIT_REASON_MSR_WRITE                    0x20
#define VM_EXIT_REASON_INVALID_GUEST_STATE          0x21
#define VM_EXIT_REASON_MSR_LOADING                  0x22
#define VM_EXIT_REASON_MWAIT_INSTRUCTION            0x24
#define VM_EXIT_REASON_MONITOR_TRAP_FLAG            0x25
#define VM_EXIT_REASON_MONITOR_INSTRUCTION          0x27
#define VM_EXIT_REASON_PAUSE_INSTRUCTION            0x28
#define VM_EXIT_REASON_MCE_DURING_VMENTRY           0x29
#define VM_EXIT_REASON_TPR_BELOW_THRESHOLD          0x2b
#define VM_EXIT_REASON_APIC_ACCESS                  0x2c
#define VM_EXIT_REASON_ACCESS_GDTR_OR_IDTR          0x2e
#define VM_EXIT_REASON_ACCESS_LDTR_OR_TR            0x2f
#define VM_EXIT_REASON_EPT_VIOLATION                0x30
#define VM_EXIT_REASON_EPT_MISCONFIG                0x31
#define VM_EXIT_REASON_INVEPT                       0x32
#define VM_EXIT_REASON_RDTSCP                       0x33
#define VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 0x34
#define VM_EXIT_REASON_INVVPID                      0x35
#define VM_EXIT_REASON_WBINVD                       0x36
#define VM_EXIT_REASON_XSETBV                       0x37
#define VM_EXIT_REASON_APIC_WRITE                   0x38
#define VM_EXIT_REASON_RDRAND                       0x39
#define VM_EXIT_REASON_INVPCID                      0x3a
#define VM_EXIT_REASON_RDSEED                       0x3d
#define VM_EXIT_REASON_PML_FULL                     0x3e
#define VM_EXIT_REASON_XSAVES                       0x3f
#define VM_EXIT_REASON_XRSTORS                      0x40
#define VM_EXIT_REASON_PCOMMIT                      0x41

// VMX assembly wrapper
extern int vmx_vmxon(uint64_t);
extern void vmx_vmptrst(uint64_t);
extern void vmx_vmptrld(uint64_t);
extern void vmx_vmclear(uint64_t);
extern void vmx_vmresume();
extern void vmx_vmlaunch();
extern uint64_t vmx_vmread(uint64_t);
extern void vmx_vmwrite(uint64_t, uint64_t);