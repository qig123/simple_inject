#include "proc_maps.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool str_contains(const char *haystack, const char *needle) {
  return haystack && needle && strstr(haystack, needle) != NULL;
}

static bool parse_maps_line(const char *line, map_entry_t *out) {
  if (!line || !out)
    return false;
  memset(out, 0, sizeof(*out));

  char perms[8] = {0};
  char dev[16] = {0};
  unsigned long inode = 0;
  char path[512] = {0};

  int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %511[^\n]", &out->start,
                 &out->end, perms, &out->offset, dev, &inode, path);
  if (n < 6)
    return false;

  out->readable = (perms[0] == 'r');
  out->writable = (perms[1] == 'w');
  out->executable = (perms[2] == 'x');

  if (n == 7)
    strncpy(out->path, path, sizeof(out->path) - 1);

  return true;
}

int find_pid_by_name(const char *name) {
  DIR *dir = opendir("/proc");
  if (!dir)
    return -1;

  struct dirent *ent = NULL;
  while ((ent = readdir(dir)) != NULL) {
    if (!isdigit((unsigned char)ent->d_name[0]))
      continue;

    int pid = atoi(ent->d_name);
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

    FILE *f = fopen(comm_path, "r");
    if (!f)
      continue;

    char buf[256];
    if (fgets(buf, sizeof(buf), f)) {
      size_t len = strlen(buf);
      if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
      if (strcmp(buf, name) == 0) {
        fclose(f);
        closedir(dir);
        return pid;
      }
    }
    fclose(f);
  }

  closedir(dir);
  return -1;
}

bool find_lib_info(int pid, const char *lib_name, lib_info_t *out) {
  if (!out || !lib_name)
    return false;
  memset(out, 0, sizeof(*out));

  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  FILE *f = fopen(maps_path, "r");
  if (!f)
    return false;

  char line[1024];
  uint64_t best_base = 0;
  char best_path[512] = {0};

  while (fgets(line, sizeof(line), f)) {
    map_entry_t entry;
    if (!parse_maps_line(line, &entry))
      continue;
    if (!str_contains(entry.path, lib_name))
      continue;
    if (entry.offset != 0)
      continue;
    if (best_base == 0 || entry.start < best_base) {
      best_base = entry.start;
      strncpy(best_path, entry.path, sizeof(best_path) - 1);
    }
  }
  fclose(f);

  if (best_base == 0)
    return false;

  out->base = best_base;
  strncpy(out->path, best_path, sizeof(out->path) - 1);
  return true;
}

static bool is_heap_candidate(const char *path) {
  if (!path || path[0] == '\0')
    return false;
  if (strcmp(path, "[heap]") == 0)
    return true;
  if (str_contains(path, "dalvik"))
    return true;
  if (str_contains(path, "malloc"))
    return true;
  if (str_contains(path, "scudo"))
    return true;
  if (str_contains(path, "heap"))
    return true;
  return false;
}

int collect_readable_maps(int pid, map_entry_t **out_maps, size_t *out_count) {
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  FILE *f = fopen(maps_path, "r");
  if (!f)
    return -1;

  size_t cap = 16;
  size_t count = 0;
  map_entry_t *arr = calloc(cap, sizeof(map_entry_t));
  if (!arr) {
    fclose(f);
    return -1;
  }

  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    map_entry_t entry;
    if (!parse_maps_line(line, &entry))
      continue;
    if (!entry.readable)
      continue;
    if (!is_heap_candidate(entry.path))
      continue;

    if (count == cap) {
      cap *= 2;
      map_entry_t *tmp = realloc(arr, cap * sizeof(map_entry_t));
      if (!tmp) {
        free(arr);
        fclose(f);
        return -1;
      }
      arr = tmp;
    }
    arr[count++] = entry;
  }

  fclose(f);

  if (count == 0) {
    free(arr);
    return -1;
  }

  *out_maps = arr;
  *out_count = count;
  return 0;
}
