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
			printk(DBG "next_base: 0x%lx\n", next_base);
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
	pgd_t* 			pgd;
	p4d_t* 			p4d;
	pud_t* 			pud;
	pmd_t* 			pmd;
	pte_t* 			pte;
	
	TEST_PTR(g->nested_pagetables, uint64_t*)
	
	// Map all pages individually
	for (offset = 0; offset < sz; offset += PAGE_SIZE) {
		if (map_to_recursive(phys_guest + offset, phys_host + offset, 3, 0, (uint64_t*)g->nested_pagetables) == ERROR) return ERROR;
	}
	
	pgd = g->nested_pagetables;
	printk(DBG "0x%lx\n", pgd);
	printk(DBG "0x%lx\n\n", pgd->pgd);
	p4d = p4d_offset(pgd, 0);
	printk(DBG "0x%lx\n", p4d);
	printk(DBG "0x%lx\n\n", p4d->pgd);
	pud = pud_offset(p4d, 0);
	printk(DBG "0x%lx\n", pud);
	printk(DBG "0x%lx\n\n", pud->pud);
	pmd = pmd_offset(pud, 0);
	printk(DBG "0x%lx\n", pmd);
	printk(DBG "0x%lx\n\n", pmd->pmd);
	pte = pte_offset_kernel(pmd, 0);
	printk(DBG "0x%lx\n", pte);
	printk(DBG "0x%lx\n\n", pte->pte);
	printk(DBG "phys_host: 0x%lx\n", phys_host);
	printk(DBG "phys_guest: 0x%lx\n", phys_guest);
	
	return SUCCESS;
}
