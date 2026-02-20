#include "elf_utils.h"

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool read_at(FILE *f, uint64_t off, void *buf, size_t size) {
  if (fseek(f, (long)off, SEEK_SET) != 0)
    return false;
  return fread(buf, 1, size, f) == size;
}

static bool vaddr_to_offset(const Elf64_Phdr *phdrs, int phnum, uint64_t vaddr,
                            uint64_t *out_off) {
  for (int i = 0; i < phnum; i++) {
    const Elf64_Phdr *p = &phdrs[i];
    if (p->p_type != PT_LOAD)
      continue;
    uint64_t vstart = p->p_vaddr;
    uint64_t vend = p->p_vaddr + p->p_memsz;
    if (vaddr >= vstart && vaddr < vend) {
      *out_off = p->p_offset + (vaddr - vstart);
      return true;
    }
  }
  return false;
}

static bool parse_gnu_hash(FILE *f, uint64_t gnu_hash_off,
                           uint64_t *out_symcount) {
  uint32_t hdr[4];
  if (!read_at(f, gnu_hash_off, hdr, sizeof(hdr)))
    return false;

  uint32_t nbuckets = hdr[0];
  uint32_t symoffset = hdr[1];
  uint32_t bloom_size = hdr[2];

  uint64_t buckets_off =
      gnu_hash_off + 16 + (uint64_t)bloom_size * sizeof(uint64_t);
  uint64_t chains_off = buckets_off + (uint64_t)nbuckets * sizeof(uint32_t);

  uint32_t max_sym = 0;
  for (uint32_t i = 0; i < nbuckets; i++) {
    uint32_t b = 0;
    if (!read_at(f, buckets_off + (uint64_t)i * 4, &b, 4))
      return false;
    if (b > max_sym)
      max_sym = b;
  }

  if (max_sym < symoffset) {
    *out_symcount = symoffset;
    return true;
  }

  uint32_t idx = max_sym;
  while (1) {
    uint32_t val = 0;
    uint64_t off = chains_off + (uint64_t)(idx - symoffset) * 4;
    if (!read_at(f, off, &val, 4))
      return false;
    idx++;
    if (val & 1)
      break;
  }

  *out_symcount = idx;
  return true;
}

bool find_symbol_offset(const char *lib_path, const char *sym_name,
                        uint64_t *out_offset) {
  FILE *f = fopen(lib_path, "rb");
  if (!f)
    return false;

  Elf64_Ehdr eh;
  if (!read_at(f, 0, &eh, sizeof(eh))) {
    fclose(f);
    return false;
  }

  if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64) {
    fclose(f);
    return false;
  }

  Elf64_Phdr *phdrs = calloc(eh.e_phnum, sizeof(Elf64_Phdr));
  if (!phdrs) {
    fclose(f);
    return false;
  }

  if (!read_at(f, eh.e_phoff, phdrs, eh.e_phnum * sizeof(Elf64_Phdr))) {
    free(phdrs);
    fclose(f);
    return false;
  }

  Elf64_Off dyn_off = 0;
  Elf64_Xword dyn_size = 0;
  for (int i = 0; i < eh.e_phnum; i++) {
    if (phdrs[i].p_type == PT_DYNAMIC) {
      dyn_off = phdrs[i].p_offset;
      dyn_size = phdrs[i].p_filesz;
      break;
    }
  }

  if (dyn_off == 0 || dyn_size == 0) {
    free(phdrs);
    fclose(f);
    return false;
  }

  size_t dyn_count = dyn_size / sizeof(Elf64_Dyn);
  Elf64_Dyn *dyns = calloc(dyn_count, sizeof(Elf64_Dyn));
  if (!dyns) {
    free(phdrs);
    fclose(f);
    return false;
  }

  if (!read_at(f, dyn_off, dyns, dyn_count * sizeof(Elf64_Dyn))) {
    free(dyns);
    free(phdrs);
    fclose(f);
    return false;
  }

  uint64_t symtab_vaddr = 0;
  uint64_t strtab_vaddr = 0;
  uint64_t strsz = 0;
  uint64_t syment = sizeof(Elf64_Sym);
  uint64_t gnu_hash_vaddr = 0;

  for (size_t i = 0; i < dyn_count; i++) {
    switch (dyns[i].d_tag) {
    case DT_SYMTAB:
      symtab_vaddr = dyns[i].d_un.d_ptr;
      break;
    case DT_STRTAB:
      strtab_vaddr = dyns[i].d_un.d_ptr;
      break;
    case DT_STRSZ:
      strsz = dyns[i].d_un.d_val;
      break;
    case DT_SYMENT:
      syment = dyns[i].d_un.d_val;
      break;
    case DT_GNU_HASH:
      gnu_hash_vaddr = dyns[i].d_un.d_ptr;
      break;
    default:
      break;
    }
  }
  free(dyns);

  if (symtab_vaddr == 0 || strtab_vaddr == 0 || strsz == 0) {
    free(phdrs);
    fclose(f);
    return false;
  }

  uint64_t symtab_off = 0;
  uint64_t strtab_off = 0;
  if (!vaddr_to_offset(phdrs, eh.e_phnum, symtab_vaddr, &symtab_off) ||
      !vaddr_to_offset(phdrs, eh.e_phnum, strtab_vaddr, &strtab_off)) {
    free(phdrs);
    fclose(f);
    return false;
  }

  uint64_t symcount = 0;
  if (gnu_hash_vaddr != 0) {
    uint64_t gnu_hash_off = 0;
    if (vaddr_to_offset(phdrs, eh.e_phnum, gnu_hash_vaddr, &gnu_hash_off))
      parse_gnu_hash(f, gnu_hash_off, &symcount);
  }

  if (symcount == 0 && strtab_off > symtab_off && syment != 0)
    symcount = (strtab_off - symtab_off) / syment;

  if (symcount == 0) {
    free(phdrs);
    fclose(f);
    return false;
  }

  char *strtab = malloc(strsz);
  if (!strtab) {
    free(phdrs);
    fclose(f);
    return false;
  }

  if (!read_at(f, strtab_off, strtab, strsz)) {
    free(strtab);
    free(phdrs);
    fclose(f);
    return false;
  }

  for (uint64_t i = 0; i < symcount; i++) {
    Elf64_Sym sym;
    uint64_t off = symtab_off + i * syment;
    if (!read_at(f, off, &sym, sizeof(sym)))
      break;
    if (sym.st_name >= strsz)
      continue;

    const char *name = strtab + sym.st_name;
    if (strcmp(name, sym_name) == 0) {
      *out_offset = sym.st_value;
      free(strtab);
      free(phdrs);
      fclose(f);
      return true;
    }
  }

  free(strtab);
  free(phdrs);
  fclose(f);
  return false;
}
