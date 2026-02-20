#pragma once

#include <stdbool.h>
#include <stdint.h>

bool find_symbol_offset(const char *lib_path, const char *sym_name,
                        uint64_t *out_offset);
