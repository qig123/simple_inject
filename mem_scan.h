#pragma once

#include <stddef.h>
#include <stdint.h>

#include "proc_maps.h"

int scan_for_pointer(int mem_fd, uint64_t target_ptr, map_entry_t *maps,
                     size_t map_count, uint64_t *out_slot);
