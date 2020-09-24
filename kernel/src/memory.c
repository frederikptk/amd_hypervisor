#include <memory.h>
#include <guest.h>
#include <mah_defs.h>
#include <debug.h>

#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/mmap_lock.h>

uint64_t get_vpn_from_level(uint64_t virt_addr, unsigned int level) {
    return (virt_addr >> (level*9 + 12)) & (uint64_t)0x1ff;
}

int map_to_recursive(uint64_t phys_guest, uint64_t phys_host, unsigned int current_level, unsigned int wanted_level, uint64_t* base, internal_guest* g) {
	uint64_t	vpn = get_vpn_from_level(phys_guest, current_level);
	uint64_t* 	next_base = NULL;
	
	TEST_PTR(base, uint64_t*,, ERROR)
	
	if (current_level == wanted_level) {
		if (wanted_level == 0) base[vpn] = phys_host | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER;
		else base[vpn] = phys_host | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_SPECIAL;
		return SUCCESS;
	} else {
		next_base = (uint64_t*)(__va(base[vpn] & PAGE_TABLE_MASK));
		
		// If a page directory is NULL, create a new one.
		if ((base[vpn] & PAGE_TABLE_MASK) == 0) {
			next_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
			kfifo_in(&k->pagetables_fifo, &next_base, sizeof(uint64_t));

			base[vpn] = __pa(next_base) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER;
			if (next_base == NULL) {
				return ERROR;
			}
		}
	}
	
	return map_to_recursive(phys_guest, phys_host, current_level - 1, wanted_level, next_base, g);
}

int map_to(uint64_t* base, unsigned long phys_guest, unsigned long phys_host, size_t sz, internal_guest* g) {
	uint64_t offset;
	
	// Map all pages individually
	for (offset = 0; offset < sz; offset += PAGE_SIZE) {
		if (map_to_recursive(phys_guest + offset, phys_host + offset, 3, 0, base, g) == ERROR) return ERROR;
	}
	
	return SUCCESS;
}

int map_user_memory(uint64_t* base, uint64_t phys_guest, uint64_t virt_user, internal_memory_region* region, internal_guest* g) {
	struct 			vm_area_struct *vma;
	int 			err;
	unsigned int 	idx;

	mmap_read_lock(current->mm);

	vma = find_vma(current->mm, virt_user);
	if (!vma) {
		err = ERROR;
		goto ret;
	}

	idx = (unsigned int)(virt_user - region->userspace_addr);

	if (idx > region->size / PAGE_SIZE) {
		err = ERROR;
		goto ret;
	}

	err = pin_user_pages(virt_user, 1, FOLL_LONGTERM | FOLL_WRITE | FOLL_FORCE, region->pages + idx, NULL);

	// TODO: get physical address of user page
	err = map_to(base, phys_guest, NULL, PAGE_SIZE, g);

ret:
	mmap_read_unlock(current->mm);

	return err;
}

int handle_pagefault(uint64_t* base, uint64_t phys_guest, internal_guest* g) {
	unsigned int i;
	internal_memory_region* region;

	// First, map the guest address which is responsible for the fault to a memory region.
	region = map_guest_addr_to_memory_region(phys_guest, g);
	
	if (region == NULL) goto err;

	// It the region is not a MMIO region, simply do lazy faulting and "swap in" the page.
	if (!region->is_mmio) {
		return map_user_memory(phys_guest, g->memory_regions[i]->guest_addr + g->memory_regions[i]->size - phys_guest, region, g);
	}

	// Else: TODO: MMIO handling
	if (region->is_mmio) {
		return SUCCESS;
	}

err:
	return ERROR;
}

int unmap_user_memory(internal_memory_region* region, internal_guest* g) {
	int 			err;

	mmap_read_lock(current->mm);

	for (i = 0; i < (region->size / PAGE_SIZE); i++) {
		if (region->pages[i] != NULL)
			unpin_user_pages(virt_user, 1, FOLL_LONGTERM | FOLL_WRITE | FOLL_FORCE, &((region->pages)[i]), NULL);

	}
	mmap_read_unlock(current->mm);

	return err;
}

int free_nested_pages(uint64_t* base, internal_guest* g) {
	int				ret;
	uint64_t		pagetable;

	// First, unmap the nested pagetables
	while (kfifo_avail(&k->pagetables_fifo)) {
		ret = kfifo_out(&k->pagetables_fifo, &pagetable, sizeof(uint64_t));
		
		if (ret != sizeof(uint64_t)) return ERROR;
		if (pagetable != NULL) kfree(pagetable);
	}

	// Next, unpin all pinned pages
	for_every_memory_region(g, unmap_user_memory, g);
}