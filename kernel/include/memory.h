#pragma once

#include <guest.h>

int map_to(internal_guest* g, unsigned long phys_guest, unsigned long phys_host, size_t sz);
