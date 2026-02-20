#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint64_t start;
  uint64_t end;
  bool readable;
  bool writable;
  bool executable;
  uint64_t offset;
  char path[512];
} map_entry_t;

typedef struct {
  uint64_t base;
  char path[512];
} lib_info_t;

int find_pid_by_name(const char *name);
bool find_lib_info(int pid, const char *lib_name, lib_info_t *out);
int collect_readable_maps(int pid, map_entry_t **out_maps, size_t *out_count);
