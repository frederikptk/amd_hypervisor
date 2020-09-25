#pragma once

#include <memory.h>
#include <mah_defs.h>
#include <stddef.h>

#include <linux/spinlock.h>
#include <linux/kfifo.h>

typedef struct internal_guest internal_guest;
typedef struct internal_vcpu internal_vcpu;
typedef struct internal_memory_region internal_memory_region;
typedef struct internal_mmu internal_mmu;

#define MAX_NUM_GUESTS          16
#define MAX_NUM_VCPUS           16
#define MAX_NUM_MEM_REGIONS     128

extern internal_guest*                 guests[MAX_NUM_GUESTS];

struct internal_guest {
    uint64_t                    id;
    void*                       arch_internal_guest; // will be casted to a arch-dependent guest type
    internal_memory_region*	    memory_regions[MAX_NUM_MEM_REGIONS];
    internal_vcpu*              vcpus[MAX_NUM_VCPUS];
    rwlock_t                    vcpu_lock;
    internal_mmu*               mmu;
} typedef internal_guest;

// Functions assume guest_list_lock to be locked.
internal_guest* map_guest_id_to_guest(uint64_t id);
int             insert_new_guest(internal_guest* g);
int             remove_guest(internal_guest* g);

// Locking the list of all guests
void guest_list_lock_read(void);
void guest_list_unlock_read(void);
void guest_list_lock_write(void);
void guest_list_unlock_write(void);

enum vcpu_state {VCPU_STATE_CREATED, VCPU_STATE_RUNNING, VCPU_STATE_PAUSED, VCPU_STATE_FAILED, VCPU_STATE_DESTROYED} typedef vcpu_state;

struct internal_vcpu {
    uint64_t                    id;
    vcpu_state		            state;
    uint64_t                    physical_core;
    void*                       arch_internal_vcpu; // will be casted to a arch-dependent guest type
} typedef internal_vcpu;

// Functions assume guest_lock to be locked.
internal_vcpu* 	map_vcpu_id_to_vcpu(uint64_t id, internal_guest* g);
int             insert_new_vcpu(internal_vcpu* vcpu, internal_guest* g);
int             remove_vcpu(internal_vcpu* vcpu, internal_guest* g);
void            for_every_vcpu(internal_guest* g, void(*callback)(internal_vcpu*, void*), void* arg);

// An abstraction for all functions provided by an hypervisor implementation.
struct internal_mah_ops {
    // Managing guests/VCPUs
    int         (*run_vcpu)(internal_vcpu*, internal_guest*);
    void*       (*create_arch_internal_vcpu)(internal_guest*);
    int         (*destroy_arch_internal_vcpu)(internal_vcpu*);
    void*       (*create_arch_internal_guest) (internal_guest*);
    void        (*destroy_arch_internal_guest)(internal_guest*);

    // Managing guest/VPU state
    void        (*set_vcpu_registers)(internal_vcpu*, user_arg_registers*);
    void        (*get_vcpu_registers)(internal_vcpu*, user_arg_registers*);
    void        (*set_memory_region) (internal_guest*, internal_memory_region*);

    // MMU-related functions
    uint64_t    (*map_page_attributes_to_arch) (uint64_t);      // map arch-independent flags to architecture flags
    uint64_t    (*map_arch_to_page_attributes) (uint64_t);      // map architecture flags to arch-independent flags
    void        (*init_mmu) (internal_mmu*);
    void        (*destroy_mmu) (internal_mmu*);
    int         (*mmu_walk_available) (hpa_t*, gpa_t, unsigned int*);
    hpa_t*      (*mmu_walk_next) (hpa_t*, gpa_t, unsigned int*);
    hpa_t*      (*mmu_walk_init) (internal_mmu*, gpa_t, unsigned int*);
} typedef internal_mah_ops;

extern internal_mah_ops mah_ops;