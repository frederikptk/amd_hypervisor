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

int map_to(hpa_t* base, gpa_t phys_guest, hpa_t phys_host, size_t sz, internal_guest* g);
int map_user_memory(hpa_t* base, gpa_t phys_guest, hva_t virt_user, internal_memory_region* region, internal_guest* g); // Called by hypervisor pagefault handler.
int handle_pagefault(hpa_t* base, gpa_t phys_guest, internal_guest* g);
int free_nested_pages(hpa_t* base, internal_guest* g);

#define PAGE_ATTRIB_READ        1 << 0 
#define PAGE_ATTRIB_WRITE       1 << 1
#define PAGE_ATTRIB_EXEC        1 << 2
#define PAGE_ATTRIB_PRESENT     1 << 3
#define PAGE_ATTRIB_DIRTY       1 << 4
#define PAGE_ATTRIB_ACCESSED    1 << 5
#define PAGE_ATTRIB_USER        1 << 6
#define PAGE_ATTRIB_HUGE        1 << 7

#define for_each_mmu_level(x,mmu,phys_guest,i) for(x = mah_ops.mmu_walk_init(mmu, phys_guest, &i); i > 0; x = mah_ops.mmu_walk_next(mmu->base, phys_guest, &i))

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