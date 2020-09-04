#include <memory.h>
#include <guest.h>
#include <mah_defs.h>
#include <debug.h>

#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/vmalloc.h>

uint64_t get_vpn_from_level(uint64_t virt_addr, unsigned int level) {
    return (virt_addr >> (level*9 + 12)) & (uint64_t)0x1ff;
}

int map_to_recursive(uint64_t phys_guest, uint64_t phys_host, unsigned int current_level, unsigned int wanted_level, uint64_t* base) {
	uint64_t	vpn = get_vpn_from_level(phys_guest, current_level);
	uint64_t* 	next_base = NULL;
	
	TEST_PTR(base, uint64_t*)
	
	if (current_level == wanted_level) {
		if (wanted_level == 0) base[vpn] = phys_host | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER;
		else base[vpn] = phys_host | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_SPECIAL;
		return SUCCESS;
	} else {
		next_base = (uint64_t*)(__va(base[vpn] & 0xFFFFFFFFFFFFF000));
		
		// If a page directory is NULL, create a new one.
		if ((base[vpn] & 0xFFFFFFFFFFFFF000) == 0) {
			next_base = kmalloc(PAGE_SIZE, GFP_KERNEL);
			base[vpn] = __pa(next_base) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER;
			if (next_base == NULL) {
				return ERROR;
			}
		}
	}
	
	return map_to_recursive(phys_guest, phys_host, current_level - 1, wanted_level, next_base);
}

int map_to(internal_guest* g, unsigned long phys_guest, unsigned long phys_host, size_t sz) {
	uint64_t offset;
	
	TEST_PTR(g->nested_pagetables, uint64_t*)
	
	// Map all pages individually
	for (offset = 0; offset < sz; offset += PAGE_SIZE) {
		if (map_to_recursive(phys_guest + offset, phys_host + offset, 3, 0, (uint64_t*)g->nested_pagetables) == ERROR) return ERROR;
	}
	
	return SUCCESS;
}
