#include <memory.h>
#include <guest.h>
#include <mah_defs.h>
#include <stddef.h>

#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/mmap_lock.h>

/*
uint64_t get_vpn_from_level(uint64_t virt_addr, unsigned int level) {
    return (virt_addr >> (level*9 + 12)) & (uint64_t)0x1ff;
}

int map_to_recursive(uint64_t phys_guest, uint64_t phys_host, unsigned int current_level, unsigned int wanted_level, uint64_t* base, internal_guest* g) {
	uint64_t	vpn = get_vpn_from_level(phys_guest, current_level);
	uint64_t* 	next_base = NULL;
	
	TEST_PTR(base, uint64_t*,, ERROR)
	
	if (current_level == wanted_level) {
		if (wanted_level == 0) base[vpn] = phys_host | mah_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
																						   PAGE_ATTRIB_WRITE | 
																						   PAGE_ATTRIB_EXEC | 
																						   PAGE_ATTRIB_PRESENT);

		else base[vpn] = phys_host | mah_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
																		 PAGE_ATTRIB_WRITE | 
																		 PAGE_ATTRIB_EXEC | 
																		 PAGE_ATTRIB_PRESENT | 
																		 PAGE_ATTRIB_HUGE);

		return SUCCESS;
	} else {
		next_base = (uint64_t*)(__va(base[vpn] & PAGE_TABLE_MASK));
		
		// TODO: insert into list

		// If a page directory is NULL, create a new one.
		if ((base[vpn] & PAGE_TABLE_MASK) == 0) {
			next_base = kzalloc(PAGE_SIZE, GFP_KERNEL);

			base[vpn] = __pa(next_base) | mah_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
																			  PAGE_ATTRIB_WRITE | 
																			  PAGE_ATTRIB_EXEC | 
																			  PAGE_ATTRIB_PRESENT);

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
*/

int map_user_memory(uint64_t *base, uint64_t phys_guest, uint64_t virt_user, internal_memory_region *region, internal_guest *g) {
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

	// TODO: error handling

	err = pin_user_pages(virt_user, 1, FOLL_LONGTERM | FOLL_WRITE | FOLL_FORCE, region->pages + idx, NULL);

	err = map_nested_pages_to(base, phys_guest, page_to_pfn(region->pages[idx]) << 12, g);

ret:
	mmap_read_unlock(current->mm);

	return err;
}

int handle_pagefault(uint64_t *base, uint64_t phys_guest, internal_guest *g) {
	internal_memory_region 	*region;

	// First, map the guest address which is responsible for the fault to a memory region.
	region = mmu_map_guest_addr_to_memory_region(phys_guest, g);
	
	if (region == NULL) goto err;

	// It the region is not a MMIO region, simply do lazy faulting and "swap in" the page.
	if (!region->is_mmio) {
		return map_user_memory(base, phys_guest, region->guest_addr + region->size - phys_guest, region, g);
	}

	// Else: TODO: MMIO handling
	if (region->is_mmio) {
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
    internal_memory_region *r;
    r = kmalloc(sizeof(pagetable), GFP_KERNEL);
    list_add_tail(&r->list_node, &m->memory_region_list);
}

void mmu_destroy_all_memory_regions(internal_mmu *m) {
    internal_memory_region *r, *tmp_r;

    list_for_each_entry_safe(r, tmp_r, &m->memory_region_list, list_node) {
        if (r != NULL) {
			if (r->pages != NULL) kfree(r->pages);
            list_del(&r->list_node);
            kfree(r);
        }
    }
}

internal_memory_region* mmu_map_guest_addr_to_memory_region(gpa_t phys_guest, internal_guest *g) {
	internal_memory_region *r;

	list_for_each_entry(r, &g->mmu->memory_region_list, list_node) {
		if (r->guest_addr >= phys_guest && (r->guest_addr + r->size) < phys_guest) {
			return r;
		}
	}

	return NULL;
}

void mmu_add_pagetable(internal_mmu* m, void* pagetable_ptr) {
    pagetable *p;
    p = kmalloc(sizeof(pagetable), GFP_KERNEL);
    list_add_tail(&p->list_node, &m->pagetables_list);
}

void mmu_destroy_all_pagetables(internal_mmu* m) {
    pagetable *p, *tmp_p;

    list_for_each_entry_safe(p, tmp_p, &m->pagetables_list, list_node) {
        if (p != NULL) {
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

    for_each_mmu_level(current_pte, g->mmu, phys_guest, level) {
        if (level == 1) {
             *current_pte = phys_host | mah_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
																			PAGE_ATTRIB_WRITE | 
																			PAGE_ATTRIB_EXEC | 
																			PAGE_ATTRIB_PRESENT);
			break;
        }

        if (mah_ops.mmu_walk_available(current_pte, phys_guest, &level) == ERROR) {
            next_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
            *current_pte = __pa(next_base) | mah_ops.map_page_attributes_to_arch(PAGE_ATTRIB_READ | 
                                                                                  PAGE_ATTRIB_WRITE | 
                                                                                  PAGE_ATTRIB_EXEC | 
                                                                                  PAGE_ATTRIB_PRESENT);
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