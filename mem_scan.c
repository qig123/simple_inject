#include "mem_scan.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define READ_CHUNK (1024 * 1024)

int scan_for_pointer(int mem_fd, uint64_t target_ptr, map_entry_t *maps,
                     size_t map_count, uint64_t *out_slot) {
  uint8_t needle[8];
  memcpy(needle, &target_ptr, sizeof(needle));

  uint8_t *buf = malloc(READ_CHUNK);
  if (!buf)
    return -1;

  for (size_t i = 0; i < map_count; i++) {
    map_entry_t *region = &maps[i];
    uint64_t addr = region->start;

    while (addr < region->end) {
      size_t to_read = READ_CHUNK;
      uint64_t remaining = region->end - addr;
      if (remaining < to_read)
        to_read = (size_t)remaining;

      ssize_t n = pread(mem_fd, buf, to_read, (off_t)addr);
      if (n <= 0)
        break;

      for (size_t off = 0; off + sizeof(needle) <= (size_t)n; off++) {
        if (memcmp(buf + off, needle, sizeof(needle)) == 0) {
          *out_slot = addr + off;
          free(buf);
          return 0;
        }
      }

      addr += (uint64_t)n;
    }
  }

  free(buf);
  return -1;
}
