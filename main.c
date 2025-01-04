#include <stdint.h>

#define PAGE_BITS 12
#define PAGE_SIZE (1 << PAGE_BITS)

#define LC_CODE_SIGNATURE 0x1d

#define CSMAGIC_REQUIREMENT0xfade0c00
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

uint8_t* put32be(uint8_t* out, uint32_t value) {
    *out++ = (value >> 24) & 0xFF;
    *out++ = (value >> 16) & 0xFF;
    *out++ = (value >> 8) & 0xFF;
    *out++ = value & 0xFF;
    return out;
}

uint8_t* put8(uint8_t* out, uint8_t value) {
    *out++ = value;
    return out;
}

uint8_t* put64be(uint8_t* out, uint64_t value) {
    *out++ = (value >> 56) & 0xFF;
    *out++ = (value >> 48) & 0xFF;
    *out++ = (value >> 40) & 0xFF;
    *out++ = (value >> 32) & 0xFF;
    *out++ = (value >> 24) & 0xFF;
    *out++ = (value >> 16) & 0xFF;
    *out++ = (value >> 8) & 0xFF;
    *out++ = value & 0xFF;
    return out;
}

uint8_t* Blob_put(Blob* b, uint8_t* out) {
    out = put32be(out, b->typ);      // Append b->typ in big-endian format
    out = put32be(out, b->offset);  // Append b->offset in big-endian format
    return out;                     // Return the updated pointer
}

#define blobSize 2 * 4

struct SuperBlob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
} typedef SuperBlob;

uint8_t* SuperBlob_put(SuperBlob* sb, uint8_t* out) {
    out = put32be(out, sb->magic);   // Append sb->magic in big-endian format
    out = put32be(out, sb->length);  // Append sb->length in big-endian format
    out = put32be(out, sb->count);   // Append sb->count in big-endian format
    return out;                      // Return the updated pointer
}

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

uint8_t* CodeDirectory_put(CodeDirectory* c, uint8_t* out) {
    out = put32be(out, c->magic);
    out = put32be(out, c->length);
    out = put32be(out, c->version);
    out = put32be(out, c->flags);
    out = put32be(out, c->hashOffset);
    out = put32be(out, c->identOffset);
    out = put32be(out, c->nSpecialSlots);
    out = put32be(out, c->nCodeSlots);
    out = put32be(out, c->codeLimit);
    out = put8(out, c->hashSize);
    out = put8(out, c->hashType);
    out = put8(out, c->_pad1);
    out = put8(out, c->pageSize);
    out = put32be(out, c->_pad2);
    out = put32be(out, c->scatterOffset);
    out = put32be(out, c->teamOffset);
    out = put32be(out, c->_pad3);
    out = put64be(out, c->codeLimit64);
    out = put64be(out, c->execSegBase);
    out = put64be(out, c->execSegLimit);
    out = put64be(out, c->execSegFlags);
    return out;
}

#define codeDirectorySize 13 * 4 + 4 + 4 * 8

struct CodeSignCmd {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t dataOffset;
  uint32_t dataSize;
} typedef CodeSignCmd;

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>  // For SHA-256
#include <dirent.h>

#define HASH_SIZE_32 32

// Size calculation function
typedef struct {
    size_t codeSize;
    const char* identifier;
} SizeArgs;

size_t CalculateSize(size_t codeSize, const char* identifier) {
    size_t nhashes = (codeSize + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t idOffset = codeDirectorySize;
    size_t hashOffset = idOffset + strlen(identifier) + 1;
    size_t codeDirSize = hashOffset + nhashes * HASH_SIZE_32;
    return superBlobSize + blobSize + codeDirSize;
}

// Signing function
typedef struct {
    uint8_t* output;
    FILE* dataFile;
    const char* identifier;
    size_t codeSize;
    size_t textOffset;
    size_t textSize;
    int isMain;
} SignArgs;

void Sign(SignArgs* args) {
    size_t nhashes = (args->codeSize + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t idOffset = codeDirectorySize;
    size_t hashOffset = idOffset + strlen(args->identifier) + 1;
    size_t totalSize = CalculateSize(args->codeSize, args->identifier);

    // Emit SuperBlob header
    SuperBlob sb = {
        .magic = CSMAGIC_EMBEDDED_SIGNATURE,
        .length = (uint32_t)totalSize,
        .count = 1
    };
    uint8_t* ptr = args->output;
    ptr = SuperBlob_put(&sb, ptr);

    // Emit Blob header
    Blob blob = {
        .typ = CSSLOT_CODEDIRECTORY,
        .offset = (uint32_t)(superBlobSize + blobSize)
    };
    ptr = Blob_put(&blob, ptr);

    // Emit CodeDirectory
    CodeDirectory cdir = {
        .magic = CSMAGIC_CODEDIRECTORY,
        .length = (uint32_t)(totalSize - (superBlobSize + blobSize)),
        .version = 0x20400,
        .flags = 0x20002, // adhoc | linkerSigned
        .hashOffset = (uint32_t)hashOffset,
        .identOffset = (uint32_t)idOffset,
        .nSpecialSlots = 0,
        .nCodeSlots = (uint32_t)nhashes,
        .codeLimit = (uint32_t)args->codeSize,
        .hashSize = HASH_SIZE_32,
        .hashType = CS_HASHTYPE_SHA256,
        .pageSize = PAGE_BITS,
        .execSegBase = args->textOffset,
        .execSegLimit = args->textSize,
        .execSegFlags = args->isMain ? CS_EXECSEG_MAIN_BINARY : 0
    };
    ptr = CodeDirectory_put(&cdir, ptr);

    // Emit identifier
    size_t idLen = strlen(args->identifier) + 1;
    memcpy(ptr, args->identifier, idLen);
    ptr += idLen;

    // Emit hashes
    uint8_t buffer[PAGE_SIZE];
    SHA256_CTX shaCtx;
    size_t readBytes = 0;
    while ((readBytes = fread(buffer, 1, PAGE_SIZE, args->dataFile)) > 0) {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256_Init(&shaCtx);
        SHA256_Update(&shaCtx, buffer, readBytes);
        SHA256_Final(hash, &shaCtx);
        memcpy(ptr, hash, HASH_SIZE_32);
        ptr += HASH_SIZE_32;
    }

    if (ferror(args->dataFile)) {
        perror("Error reading file");
        exit(EXIT_FAILURE);
    }
}

void SignApp(const char* appPath, const char* identifier) {
    DIR* dir = opendir(appPath);
    if (!dir) {
        perror("Failed to open .app directory");
        exit(EXIT_FAILURE);
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, "Mach-O") != NULL) {
            char filePath[1024];
            snprintf(filePath, sizeof(filePath), "%s/%s", appPath, entry->d_name);

            FILE* dataFile = fopen(filePath, "rb");
            if (!dataFile) {
                perror("Failed to open Mach-O file");
                closedir(dir);
                exit(EXIT_FAILURE);
            }

            fseek(dataFile, 0, SEEK_END);
            size_t codeSize = ftell(dataFile);
            rewind(dataFile);

            uint8_t* output = malloc(CalculateSize(codeSize, identifier));
            if (!output) {
                perror("Memory allocation failed");
                fclose(dataFile);
                closedir(dir);
                exit(EXIT_FAILURE);
            }

            SignArgs args = {
                .output = output,
                .dataFile = dataFile,
                .identifier = identifier,
                .codeSize = codeSize,
                .textOffset = 0x1000,
                .textSize = 0x2000,
                .isMain = 1
            };

            Sign(&args);

            fclose(dataFile);
            free(output);
        }
    }

    closedir(dir);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <app_path> <identifier>\n", argv[0]);
        return 1;
    }

    const char* appPath = argv[1];
    const char* identifier = argv[2];

    SignApp(appPath, identifier);

    return 0;
}

