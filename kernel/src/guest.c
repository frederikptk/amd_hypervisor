#include <guest.h>

internal_guest* guest;

internal_vcpu* map_vcpu_id_to_vcpu(uint8_t id, internal_guest* g) {
	internal_vcpu* current_vcpu = g->vcpus;
	
	while (current_vcpu->next != NULL) {
		if (current_vcpu->id == id) break;
		current_vcpu = current_vcpu->next;
	}
	
	return current_vcpu;
}
