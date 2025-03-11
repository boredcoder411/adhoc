#pragma once

#include <stdint.h>
#include <openssl/sha.h>
#include <stdio.h>

#define OPENSSL_SUPPRESS_DEPRECATED

#define PAGE_BITS 12
#define PAGE_SIZE (1 << PAGE_BITS)

#define LC_CODE_SIGNATURE 0x1d

#define CSMAGIC_REQUIREMENT 0xfade0c00
#define CSMAGIC_REQUIREMENTS 0xfade0c01
#define CSMAGIC_CODEDIRECTORY 0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1

#define CSSLOT_CODEDIRECTORY 0

#define CS_HASHTYPE_SHA1 1
#define CS_HASHTYPE_SHA256 2
#define CS_HASHTYPE_SHA256_TRUNCATED 3
#define CS_HASHTYPE_SHA384 4

#define CS_EXECSEG_MAIN_BINARY 0x1
#define CS_EXECSEG_ALLOW_UNSIGNED 0x10
#define CS_EXECSEG_DEBUGGER 0x20
#define CS_EXECSEG_JIT 0x40
#define CS_EXECSEG_SKIP_LV 0x80
#define CS_EXECSEG_CAN_LOAD_CDHASH 0x100
#define CS_EXECSEG_CAN_EXEC_CDHASH 0x200

struct Blob {
  uint32_t typ;
  uint32_t offset;
} typedef Blob;

#define blobSize 2 * 4

struct SuperBlob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
} typedef SuperBlob;

#define superBlobSize 3 * 4

struct CodeDirectory {
  uint32_t magic;
  uint32_t length;
  uint32_t version;
  uint32_t flags;
  uint32_t hashOffset;
  uint32_t identOffset;
  uint32_t nSpecialSlots;
  uint32_t nCodeSlots;
  uint32_t codeLimit;
  uint8_t hashSize;
  uint8_t hashType;
  uint8_t _pad1;
  uint8_t pageSize;
  uint32_t _pad2;
  uint32_t scatterOffset;
  uint32_t teamOffset;
  uint32_t _pad3;
  uint64_t codeLimit64;
  uint64_t execSegBase;
  uint64_t execSegLimit;
  uint64_t execSegFlags;
  // data follows
} typedef CodeDirectory;

#define codeDirectorySize 13 * 4 + 4 + 4 * 8

struct CodeSignCmd {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t dataOffset;
  uint32_t dataSize;
} typedef CodeSignCmd;

#define HASH_SIZE_32 32

// Size calculation function
typedef struct {
    size_t codeSize;
    const char* identifier;
} SizeArgs;

typedef struct {
    uint8_t* output;
    FILE* dataFile;
    const char* identifier;
    size_t codeSize;
    size_t textOffset;
    size_t textSize;
    int isMain;
} SignArgs;
