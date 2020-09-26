#include <memory.h>
#include <guest.h>
#include <mah_defs.h>
#include <stddef.h>

#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/mmap_lock.h>

int map_user_memory(uint64_t *base, uint64_t phys_guest, uint64_t virt_user, internal_memory_region *region, internal_guest *g) {
	struct 			vm_area_struct *vma;
	int 			err;
	unsigned int 	idx;

	printk(DBG "map_user_memory\n");

	mmap_read_lock(current->mm);

	vma = find_vma(current->mm, virt_user);
	if (!vma) {
		printk(DBG "vma not found!\n");
		err = ERROR;
		goto ret;
	}

	idx = (unsigned int)(virt_user - region->userspace_addr) / PAGE_SIZE;

	if (idx > region->size / PAGE_SIZE) {
		printk(DBG "idx out of range: 0x%lx\n", (unsigned long)idx);
		err = ERROR;
		goto ret;
	}

	// TODO: error handling

	printk(DBG "pinning user page: 0x%lx\n", (unsigned long)virt_user);
	err = pin_user_pages(virt_user, 1, FOLL_LONGTERM | FOLL_WRITE | FOLL_FORCE, region->pages + idx, NULL);

	err = map_nested_pages_to(base, phys_guest, page_to_pfn(region->pages[idx]) << 12, g);

ret:
	mmap_read_unlock(current->mm);

	return err;
}

int handle_pagefault(uint64_t *base, uint64_t phys_guest, uint64_t reason, internal_guest *g) {
	internal_memory_region 	*region;

	printk(DBG "handle_pagefault, reason: 0x%lx\n", reason);

	// First, map the guest address which is responsible for the fault to a memory region.
	region = mmu_map_guest_addr_to_memory_region(phys_guest, g);

	printk(DBG "Found memory region: 0x%lx\n", (unsigned long)region);
	
	if (region == NULL) goto err;

	// It the region is not a MMIO region, simply do lazy faulting and "swap in" the page.
	if (!region->is_mmio) {
		printk(DBG "no MMIO\n");
		if (reason & PAGEFAULT_NON_PRESENT)
			map_user_memory(base, phys_guest, region->userspace_addr + (region->guest_addr - phys_guest), region, g);
	}

	// Else: TODO: MMIO handling
	if (region->is_mmio) {
		printk(DBG "MMIO\n");
		return SUCCESS;
	}

err:
	return ERROR;
}

void unmap_user_memory(internal_memory_region *region) {
	int				i;

	mmap_read_lock(current->mm);

	for (i = 0; i < (region->size / PAGE_SIZE); i++) {
		if (region->pages[i] != NULL)
			unpin_user_pages(&((region->pages)[i]), 1);

	}
	mmap_read_unlock(current->mm);
}

void mmu_add_memory_region(internal_mmu *m, internal_memory_region *region) {
    list_add_tail(&region->list_node, &m->memory_region_list);

	printk(DBG "Adding memory region: 0x%lx\n", (unsigned long)region);
}

void mmu_destroy_all_memory_regions(internal_mmu *m) {
    internal_memory_region *r, *tmp_r;

    list_for_each_entry_safe(r, tmp_r, &m->memory_region_list, list_node) {
        if (r != NULL) {
			printk(DBG "Removing memory region: 0x%lx\n", (unsigned long)r);

			if (r->pages != NULL) kfree(r->pages);
            list_del(&r->list_node);
            kfree(r);
        }
    }
}

internal_memory_region* mmu_map_guest_addr_to_memory_region(gpa_t phys_guest, internal_guest *g) {
	internal_memory_region *r;

	list_for_each_entry(r, &g->mmu->memory_region_list, list_node) {
		//printk(DBG "\tLooking @ memory region: 0x%lx, @ guest addr: 0x%lx\n", (unsigned long)r, (unsigned long)r->guest_addr);
		if (r->guest_addr <= phys_guest && (r->guest_addr + r->size) > phys_guest) {
			return r;
		}
	}

	return NULL;
}

void mmu_add_pagetable(internal_mmu* m, void* pagetable_ptr) {
    pagetable *p;
    p = kmalloc(sizeof(pagetable), GFP_KERNEL);
    list_add_tail(&p->list_node, &m->pagetables_list);

	printk(DBG "Adding pagetable: 0x%lx\n", (unsigned long)pagetable_ptr);
}

void mmu_destroy_all_pagetables(internal_mmu* m) {
    pagetable *p, *tmp_p;

    list_for_each_entry_safe(p, tmp_p, &m->pagetables_list, list_node) {
        if (p != NULL) {
			printk(DBG "Removing pagetable: 0x%lx\n", (unsigned long)p->pagetable);

			if (p->pagetable != NULL) kfree(p->pagetable);
            list_del(&p->list_node);
            kfree(p);
        }
    }
}

int map_nested_pages_to(hpa_t *base, gpa_t phys_guest, hpa_t phys_host, internal_guest *g) {
    unsigned int    level;
    hpa_t          	*current_pte;
	hpa_t			*next_base;

	printk(DBG "map_nested_pages_to\n");

    for_each_mmu_level(current_pte, g->mmu, phys_guest, level) {
		printk(DBG "current_pte va: 0x%lx\n", (unsigned long)*current_pte);
		printk(DBG "current_pte pa: 0x%lx\n", (unsigned long)__pa(*current_pte));
		printk(DBG "level: 0x%lx\n", (unsigned long)level);

        if (level == 1) {
             *current_pte = phys_host | mah_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
																			PAGE_ATTRIB_WRITE | 
																			PAGE_ATTRIB_EXEC | 
																			PAGE_ATTRIB_PRESENT);
			break;
        }

        if (mah_ops.mmu_walk_available(current_pte, phys_guest, &level) == ERROR) {
            next_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
			mmu_add_pagetable(g->mmu, next_base);
			printk(DBG "next_base: 0x%lx\n", (unsigned long)next_base);
            *current_pte = __pa(next_base) | mah_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
                                                                                  PAGE_ATTRIB_WRITE | 
                                                                                  PAGE_ATTRIB_EXEC | 
                                                                                  PAGE_ATTRIB_PRESENT);
			printk(DBG "*current_pte: 0x%lx\n", (unsigned long)*current_pte);
            if (next_base == NULL) {
				return ERROR;
			}
        }
    }

    return SUCCESS;
}

int set_pagetable_attributes(gpa_t phys_guest, uint64_t attributes, internal_guest *g) {
	unsigned int    level;
    hpa_t	        *current_pte;

    for_each_mmu_level(current_pte, g->mmu, phys_guest, level) {
        if (level == 1) {
            *current_pte = (*current_pte & PAGE_TABLE_MASK) | mah_ops.map_page_attributes_to_arch(attributes);
			break;
        }
    }

    return SUCCESS;
}

int get_pagetable_attributes(gpa_t phys_guest, internal_guest* g) {
	unsigned int    level;
    hpa_t          	*current_pte;

    for_each_mmu_level(current_pte, g->mmu, phys_guest, level) {
        if (level == 1) {
            return mah_ops.map_arch_to_page_attributes(*current_pte);
        }
    }

    return SUCCESS;
}