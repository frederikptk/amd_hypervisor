#pragma once

#include <memory.h>
#include <mah_defs.h>

#include <linux/spinlock.h>

typedef struct internal_guest internal_guest;
typedef struct internal_vcpu internal_vcpu;
typedef struct internal_memory_region internal_memory_region;

#define MAX_NUM_GUESTS          16
#define MAX_NUM_VCPUS           16

extern internal_guest*                 guests[MAX_NUM_GUESTS];

struct internal_guest {
    uint64_t                    id;
    void*                       arch_internal_guest; // will be casted to a arch-dependent guest type
    internal_memory_region*	    memory_regions;
    internal_vcpu*              vcpus[MAX_NUM_VCPUS];
    rwlock_t                    vcpu_lock;
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
    int     (*run_vcpu)(internal_vcpu*);

    void*   (*create_arch_internal_vcpu)(internal_guest*);
    int     (*destroy_arch_internal_vcpu)(internal_vcpu*);
    void*   (*create_arch_internal_guest) (void);
    void    (*destroy_arch_internal_guest)(internal_guest*);

    void    (*set_vcpu_registers)(internal_vcpu*, user_arg_registers*);
    void    (*get_vcpu_registers)(internal_vcpu*, user_arg_registers*);
    void    (*set_memory_region) (internal_guest*, internal_memory_region*);
} typedef internal_mah_ops;

extern internal_mah_ops mah_ops;