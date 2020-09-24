#pragma once

#include <linux/types.h>

#include <guest.h>

typedef struct internal_guest internal_guest;

#define PAGE_TABLE_MASK             (uint64_t)0xFFFFFFFFFFFFF000

struct internal_memory_region {
    uint64_t            userspace_addr;
    uint64_t            guest_addr;
    uint64_t            size;
    int                 is_present;
    int                 is_mmio;
    struct page         **pages;
} typedef internal_memory_region;

int map_to(uint64_t* base, unsigned long phys_guest, unsigned long phys_host, size_t sz);
int map_user_memory(uint64_t* base, uint64_t phys_guest, uint64_t virt_user, internal_memory_region* region, internal_guest* g); // Called by hypervisor pagefault handler.
int handle_pagefault(uint64_t* base, uint64_t phys_guest, internal_guest* g);
int free_nested_pages(uint64_t* base, internal_guest* g);