#include <guest.h>
#include <stddef.h>

#include <linux/slab.h>

internal_hyperkraken_ops        hyperkraken_ops;

static                          DEFINE_MUTEX(g_guests_mutex);
internal_guest*                 g_guests[MAX_NUM_GUESTS];

void guest_list_lock(void) {
	mutex_lock(&g_guests_mutex);
}

void guest_list_unlock(void) {
	mutex_unlock(&g_guests_mutex);
}

void guest_vcpu_read_lock(internal_guest* g) {
    down_read(&g->vcpu_lock);
}

void guest_vcpu_read_unlock(internal_guest* g) {
    up_read(&g->vcpu_lock);
}

void guest_vcpu_write_lock(internal_guest* g) {
    down_write(&g->vcpu_lock);
}

void guest_vcpu_write_unlock(internal_guest* g) {
    up_write(&g->vcpu_lock);
}

void destroy_guest(internal_guest *g) {
	if (g != NULL) {
		// Destroy all VCPUs first.
		for_every_vcpu(g, (void(*)(internal_vcpu*, void*))hyperkraken_ops.destroy_arch_internal_vcpu, NULL);
		for_every_vcpu(g, (void(*)(internal_vcpu*, void*))remove_vcpu, g);
		for_every_vcpu(g, (void(*)(internal_vcpu*, void*))kfree, NULL);

		// Destroy the MMU: pagetables, memory regions, internals
		if (g->mmu != NULL) {
			hyperkraken_ops.destroy_mmu(g->mmu);
			mmu_destroy_all_memory_regions(g->mmu);
			mmu_destroy_all_pagetables(g->mmu);
			kfree(g->mmu);
		}

        destroy_all_breakpoints(g);

		// Free all other pointers.
		hyperkraken_ops.destroy_arch_internal_guest(g);
		remove_guest(g);
		kfree(g);
	}
}

internal_guest* create_guest(void) {
	internal_guest				*g;
	internal_mmu				*mmu;

	// Create the guest itself
	g = (internal_guest*)kmalloc(sizeof(internal_guest), GFP_KERNEL);
	if (g == NULL) goto err;

	// Create the MMU for the guest
	mmu = kmalloc(sizeof(internal_mmu), GFP_KERNEL);
	if (mmu == NULL) goto err;
	hyperkraken_ops.init_mmu(mmu);
	g->mmu = mmu;

	// Initialize the arch-dependent structure for the guest
	g->arch_internal_guest = hyperkraken_ops.create_arch_internal_guest(g);
	if (g->arch_internal_guest == NULL) goto err;

	hash_init(g->breakpoints);

	init_rwsem(&g->vcpu_lock);

	return g;

err:
	destroy_guest(g);
	return NULL;
}

internal_guest* map_guest_id_to_guest(uint64_t id) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_GUESTS; i++) {
        if (g_guests[i] != NULL) {
            if (g_guests[i]->id == id) return g_guests[i];
        }
    }

    return (internal_guest*)NULL;
}

int insert_new_guest(internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_GUESTS; i++) {
        if (g_guests[i] == NULL) {
            g->id = i;
            g_guests[i] = g;
            return 0;
        }
    }

    return -EINVAL;
}

int remove_guest(internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_GUESTS; i++) {
        if (g_guests[i] == g) {
            g_guests[i] = NULL;
            return 0;
        }
    }

    return -EINVAL;
}

internal_vcpu* map_vcpu_id_to_vcpu(uint64_t id, internal_guest* g) {
	unsigned int i;

    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (g->vcpus[i] != NULL) {
            if (g->vcpus[i]->id == id) return g->vcpus[i];
        }
    }

    return (internal_vcpu*)NULL;
}

int insert_new_vcpu(internal_vcpu* vcpu, internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (g->vcpus[i] == NULL) {
            vcpu->id = g->id + i;
            g->vcpus[i] = vcpu;
            printk(DBG "Inserting VCPU: 0x%lx\n", (unsigned long)vcpu);
            return 0;
        }
    }

    return -EINVAL;
}

int remove_vcpu(internal_vcpu* vcpu, internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (g->vcpus[i] == vcpu) {
            printk(DBG "Removing VCPU: 0x%lx\n", (unsigned long)vcpu);
            g->vcpus[i] = NULL;
            return 0;
        }
    }

    return -EINVAL;
}

void for_every_vcpu(internal_guest* g, void(*callback)(internal_vcpu*, void*), void* arg) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (g->vcpus[i] != NULL) {
            callback(g->vcpus[i], arg);
        }
    }
}

internal_breakpoint* find_breakpoint_by_gpa(internal_guest *g, gpa_t guest_addr) {
    int                 bkt;
    internal_breakpoint *bp;

    hash_for_each(g->breakpoints, bkt, bp, hlist) {
        if (guest_addr == bp->guest_addr_p) return bp;
    }

    return NULL;
}

internal_breakpoint* find_breakpoint_by_gva(internal_guest *g, gva_t guest_addr) {
    internal_breakpoint *bp;

    hash_for_each_possible(g->breakpoints, bp, hlist, guest_addr) {
        if (guest_addr == bp->guest_addr_v) return bp;
    }

    return NULL;
}

void insert_breakpoint(internal_guest *g, internal_breakpoint* bp) {
    hash_add(g->breakpoints, &bp->hlist, bp->guest_addr_v);
}

void remove_breakpoint(internal_guest *g, internal_breakpoint* bp) {
    hash_del(&bp->hlist);
}

void destroy_all_breakpoints(internal_guest *g) {
    int                 bkt;
    struct hlist_node   *h;
    internal_breakpoint *bp;

    hash_for_each_safe(g->breakpoints, bkt, h, bp, hlist) {
        if (bp != NULL) {
            // Don't do the arch-dependent cleanup here. Since destroy_all_breakpoints() will be called
            // by destroy_guest(), the guest memory won't be used anymore. So leaving the breakpoint
            // instructions in memory is safe.
            remove_breakpoint(g, bp);
            kfree(bp);
        }
    }
}