#pragma once

#include <stdint.h>

typedef int32_t cpu_type_t;
typedef int32_t cpu_subtype_t;
typedef int vm_prot_t;

#define LC_CODE_SIGNATURE 0x1d

typedef struct {
  uint32_t magic;
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
} mach_header;

#define MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe

typedef struct {
        uint32_t magic;
        cpu_type_t cputype;
        cpu_subtype_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;
        uint32_t reserved;
} mach_header_64;

#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe

typedef struct {
        uint32_t cmd;
        uint32_t cmdsize;
} load_command;

#define LC_SEGMENT 0x1
#define LC_SEGMENT_64 0x19

typedef struct {
        uint32_t cmd;
        uint32_t cmdsize;
        char segname[16];
        uint32_t vmaddr;
        uint32_t vmsize;
        uint32_t fileoff;
        uint32_t filesize;
        vm_prot_t maxprot;
        vm_prot_t initprot;
        uint32_t nsects;
        uint32_t flags;
} segment_command;

typedef struct {
        uint32_t cmd;
        uint32_t cmdsize;
        char segname[16];
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        uint64_t filesize;
        vm_prot_t maxprot;
        vm_prot_t initprot;
        uint32_t nsects;
        uint32_t flags;
} segment_command_64;

typedef struct {
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
} section;

typedef struct {
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
} section_64;
