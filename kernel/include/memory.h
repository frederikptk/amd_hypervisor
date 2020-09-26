#pragma once

#include <guest.h>
#include <stddef.h>

#include <linux/list.h>
#include <linux/types.h>

typedef struct internal_guest internal_guest;

#define PAGE_TABLE_MASK             (uint64_t)0x7FFFFFFFFFFFF000 // Also mask out NX bit (bit 63)

struct internal_memory_region {
    hva_t               userspace_addr;
    gpa_t               guest_addr;
    uint64_t            size;
    int                 is_present;
    int                 is_mmio;
    struct page         **pages;
    struct list_head    list_node;
} typedef internal_memory_region;

#define PAGEFAULT_NON_PRESENT   ((uint64_t)1 << 0)
#define PAGEFAULT_WRITE         ((uint64_t)1 << 1)
#define PAGEFAULT_READ          ((uint64_t)1 << 2)
#define PAGEFAULT_EXEC          ((uint64_t)1 << 3)
#define PAGEFAULT_UNKNOWN       ((uint64_t)1 << 4)

int map_to(hpa_t* base, gpa_t phys_guest, hpa_t phys_host, size_t sz, internal_guest* g);
int map_user_memory(hpa_t* base, gpa_t phys_guest, hva_t virt_user, internal_memory_region* region, internal_guest* g); // Called by hypervisor pagefault handler.
int handle_pagefault(hpa_t* base, gpa_t phys_guest, uint64_t reason, internal_guest* g);
int free_nested_pages(hpa_t* base, internal_guest* g);

#define PAGE_ATTRIB_READ        ((uint64_t)1 << 0)
#define PAGE_ATTRIB_WRITE       ((uint64_t)1 << 1)
#define PAGE_ATTRIB_EXEC        ((uint64_t)1 << 2)
#define PAGE_ATTRIB_PRESENT     ((uint64_t)1 << 3)
#define PAGE_ATTRIB_DIRTY       ((uint64_t)1 << 4)
#define PAGE_ATTRIB_ACCESSED    ((uint64_t)1 << 5)
#define PAGE_ATTRIB_USER        ((uint64_t)1 << 6)
#define PAGE_ATTRIB_HUGE        ((uint64_t)1 << 7)

#define for_each_mmu_level(x,mmu,phys_guest,i) for(x = mah_ops.mmu_walk_init(mmu, phys_guest, &i); i > 0; x = mah_ops.mmu_walk_next(x, phys_guest, &i))

struct pagetable {
    void*               pagetable;
    struct list_head    list_node;
} typedef pagetable;

struct internal_mmu {
    hpa_t*              base;
    unsigned int        levels;
    struct list_head    pagetables_list; // will be filled with pagetables in order to allow cleanup upon guest destruction
    struct list_head    memory_region_list;
} typedef internal_mmu;

void mmu_add_memory_region(internal_mmu* m, internal_memory_region* region);
void mmu_destroy_all_memory_regions(internal_mmu* m);
internal_memory_region* mmu_map_guest_addr_to_memory_region(gpa_t phys_guest, internal_guest *g);
void mmu_add_pagetable(internal_mmu* m, void* pagetable_ptr);
void mmu_destroy_all_pagetables(internal_mmu* m);
int  map_nested_pages_to(hpa_t* base, gpa_t phys_guest, hpa_t phys_host, internal_guest* g);
int  set_pagetable_attributes(gpa_t phys_guest, uint64_t attributes, internal_guest* g);
int  get_pagetable_attributes(gpa_t phys_guest, internal_guest* g);