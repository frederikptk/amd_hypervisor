#pragma once

 #include <linux/list.h>

#include <guest.h>

typedef struct internal_guest internal_guest;

struct internal_memory_region {
    uint64_t            userspace_addr;
    uint64_t            guest_addr;
    uint64_t            size;
    int                 is_present;
    int                 is_mmio;
    struct list_head    list;
} typedef internal_memory_region;

int map_to(uint64_t* base, unsigned long phys_guest, unsigned long phys_host, size_t sz);