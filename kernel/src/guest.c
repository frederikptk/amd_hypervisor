#include <guest.h>
#include <debug.h>

internal_mah_ops mah_ops;
static DEFINE_RWLOCK(guest_list_lock);
internal_guest*                 guests[MAX_NUM_GUESTS];

void guest_list_lock_read(void) {
	read_lock(&guest_list_lock);
}

void guest_list_unlock_read(void) {
	read_unlock(&guest_list_lock);
}

void guest_list_lock_write(void) {
	write_lock(&guest_list_lock);
}

void guest_list_unlock_write(void) {
	write_unlock(&guest_list_lock);
}

internal_guest* map_guest_id_to_guest(uint64_t id) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_GUESTS; i++) {
        if (guests[i] != NULL) {
            if (guests[i]->id == id) return guests[i];
        }
    }

    return (internal_guest*)NULL;
}

int insert_new_guest(internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_GUESTS; i++) {
        if (guests[i] == NULL) {
            g->id = i;
            guests[i] = g;
            return SUCCESS;
        }
    }

    return ERROR;
}

int remove_guest(internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_GUESTS; i++) {
        if (guests[i] == g) {
            guests[i] = NULL;
            return SUCCESS;
        }
    }

    return ERROR;
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
            return SUCCESS;
        }
    }

    return ERROR;
}

int remove_vcpu(internal_vcpu* vcpu, internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (g->vcpus[i] == vcpu) {
            g->vcpus[i] = NULL;
            return SUCCESS;
        }
    }

    return ERROR;
}

void for_every_vcpu(internal_guest* g, void(*callback)(internal_vcpu*, void*), void* arg) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (g->vcpus[i] != NULL) {
            callback(g->vcpus[i], arg);
        }
    }
}

internal_memory_region* map_guest_addr_to_memory_region(uint64_t phys_guest, internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_MEM_REGIONS; i++) {
		if (g->memory_regions[i] != NULL) {
			if (g->memory_regions[i]->guest_addr >= phys_guest && (g->memory_regions[i]->guest_addr + g->memory_regions[i]->size) < phys_guest) {
				return g->memory_regions[i];
			}
		}
	}

    return NULL;
}

int insert_new_memory_region(internal_memory_region* memory_region, internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_MEM_REGIONS; i++) {
        if (g->memory_regions[i] == NULL) {
            g->memory_regions[i] = memory_region;
            return SUCCESS;
        }
    }

    return ERROR;
}

int remove_memory_region(internal_memory_region* memory_region, internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_MEM_REGIONS; i++) {
        if (g->memory_regions[i] == memory_region) {
            g->memory_regions[i] = NULL;
            return SUCCESS;
        }
    }

    return ERROR;
}

void for_every_memory_region(internal_guest* g, void(*callback)(internal_memory_region*, void*), void* arg) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_MEM_REGIONS; i++) {
        if (g->memory_regions[i] != NULL) {
            callback(g->memory_regions[i], arg);
        }
    }
}