#include <guest.h>
#include <stddef.h>

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
            printk(DBG "Inserting VCPU: 0x%lx\n", (unsigned long)vcpu);
            return SUCCESS;
        }
    }

    return ERROR;
}

int remove_vcpu(internal_vcpu* vcpu, internal_guest* g) {
    unsigned int i;

    for (i = 0; i < MAX_NUM_VCPUS; i++) {
        if (g->vcpus[i] == vcpu) {
            printk(DBG "Removing VCPU: 0x%lx\n", (unsigned long)vcpu);
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