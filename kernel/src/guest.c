#include <guest.h>

internal_guest* guest;
static DEFINE_RWLOCK(guest_lock);

internal_vcpu* map_vcpu_id_to_vcpu(uint8_t id, internal_guest* g) {
	internal_vcpu* current_vcpu = g->vcpus;
	
	while (current_vcpu->next != NULL) {
		if (current_vcpu->id == id) break;
		current_vcpu = current_vcpu->next;
	}
	
	return current_vcpu;
}

void update_intercept_reasons(internal_guest* g) {
	internal_vcpu* current_vcpu;

	if(g == NULL) return;

	current_vcpu = g->vcpus;
	
	while (current_vcpu->next != NULL) {
		if (current_vcpu == NULL) break;
		
		if (current_vcpu->vcpu_vmcb == NULL) {
			current_vcpu = current_vcpu->next;
			continue;
		}

		current_vcpu->vcpu_vmcb->intercept_exceptions = g->intercept_exceptions;
		current_vcpu->vcpu_vmcb->intercept = g->intercept;
		
		current_vcpu = current_vcpu->next;
	}
	
}

void guest_lock_read(void) {
	read_lock(&guest_lock);
}

void guest_unlock_read(void) {
	read_unlock(&guest_lock);
}

void guest_lock_write(void) {
	write_lock(&guest_lock);
}

void guest_unlock_write(void) {
	write_unlock(&guest_lock);
}