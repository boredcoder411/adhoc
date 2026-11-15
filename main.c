/*
 * Ad-hoc Mach-O signer.
 *
 * The code signature blob layout is based on Go's linker implementation:
 * https://tip.golang.org/src/cmd/internal/codesign/codesign.go?m=text
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include "signing/identity.h"
#if defined(ADHOC_SIGNER_WASM) && defined(__EMSCRIPTEN__)
#include <emscripten/emscripten.h>
#define WASM_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define WASM_EXPORT
#endif

#include "macho/constants.h"
#include "signing/constants.h"

#define MH_EXECUTE 0x2

static size_t align_up(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static uint32_t read32le(const uint8_t* in) {
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static uint64_t read64le(const uint8_t* in) {
    return ((uint64_t)read32le(in)) | ((uint64_t)read32le(in + 4) << 32);
}

static void write32le(uint8_t* out, uint32_t value) {
    out[0] = value & 0xff;
    out[1] = (value >> 8) & 0xff;
    out[2] = (value >> 16) & 0xff;
    out[3] = (value >> 24) & 0xff;
}

static void write64le(uint8_t* out, uint64_t value) {
    write32le(out, (uint32_t)value);
    write32le(out + 4, (uint32_t)(value >> 32));
}

static void write32be(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint8_t* put8(uint8_t* out, uint8_t value) {
    *out++ = value;
    return out;
}

static uint8_t* put32be(uint8_t* out, uint32_t value) {
    *out++ = (value >> 24) & 0xff;
    *out++ = (value >> 16) & 0xff;
    *out++ = (value >> 8) & 0xff;
    *out++ = value & 0xff;
    return out;
}

static uint8_t* put64be(uint8_t* out, uint64_t value) {
    *out++ = (value >> 56) & 0xff;
    *out++ = (value >> 48) & 0xff;
    *out++ = (value >> 40) & 0xff;
    *out++ = (value >> 32) & 0xff;
    *out++ = (value >> 24) & 0xff;
    *out++ = (value >> 16) & 0xff;
    *out++ = (value >> 8) & 0xff;
    *out++ = value & 0xff;
    return out;
}

#ifdef ADHOC_SIGNER_WASM
static uint32_t rotr32(uint32_t value, unsigned int bits) {
    return (value >> bits) | (value << (32 - bits));
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void sha256_digest(const uint8_t* data, size_t len, uint8_t out[HASH_SIZE_32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    size_t fullBlocks = len / 64;
    for (size_t i = 0; i < fullBlocks; i++) {
        sha256_transform(state, data + i * 64);
    }

    uint8_t finalBlocks[128] = {0};
    size_t remaining = len % 64;
    memcpy(finalBlocks, data + fullBlocks * 64, remaining);
    finalBlocks[remaining] = 0x80;

    size_t finalSize = remaining >= 56 ? 128 : 64;
    uint64_t bitLen = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        finalBlocks[finalSize - 1 - i] = (uint8_t)(bitLen >> (i * 8));
    }

    sha256_transform(state, finalBlocks);
    if (finalSize == 128) {
        sha256_transform(state, finalBlocks + 64);
    }

    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)state[i];
    }
}
#else
static void sha256_digest(const uint8_t* data, size_t len, uint8_t out[HASH_SIZE_32]) {
    SHA256(data, len, out);
}
#endif

static uint8_t* CodeDirectory_put(const CodeDirectory* c, uint8_t* out) {
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

#define PAD4(n) (((n) + 3) & ~(size_t)3)

// Everything that goes into the signature besides the code itself.
typedef struct {
    const char* identifier;
    const char* teamID;          // NULL when signing ad-hoc
    const uint8_t* requirements; // requirements blob or NULL
    size_t requirementsLen;
    const uint8_t* entitlements; // entitlements blob or NULL
    size_t entitlementsLen;
} SigMeta;

typedef struct {
    const char* p12Path;
    const char* p12Pass;
    const char* teamID;
    const char* entitlementsPath;
    const uint8_t* p12Data;
    size_t p12Size;
    const uint8_t* entitlementsData;
    size_t entitlementsSize;
} SignOptions;

static uint8_t* put_data_field(uint8_t* out, const uint8_t* data, size_t len) {
    out = put32be(out, (uint32_t)len);
    memcpy(out, data, len);
    out += len;
    size_t pad = PAD4(len) - len;
    memset(out, 0, pad);
    return out + pad;
}

static uint8_t* build_entitlements_blob(const uint8_t* xml, size_t len, size_t* outLen) {
    size_t total = 8 + len;
    uint8_t* blob = malloc(total);
    if (blob == NULL) {
        return NULL;
    }
    write32be(blob, CSMAGIC_EMBEDDED_ENTITLEMENTS);
    write32be(blob + 4, (uint32_t)total);
    memcpy(blob + 8, xml, len);
    *outLen = total;
    return blob;
}

// Builds the designated requirement as a requirements set holding one entry:
//   identifier "<id>" and certificate leaf[subject.OU] = "<team id>"
// When no team ID applies (e.g. a self-signed certificate), it falls back to
// the form codesign itself uses in that case:
//   identifier "<id>" and certificate leaf hashes to <sha1 of the certificate>
static uint8_t* build_requirements_blob(const char* identifier, const SignerIdentity* identity,
                                        const char* teamID, size_t* outLen) {
    static const char kSubjectOU[] = "subject.OU";
    size_t idLen = strlen(identifier);
    size_t teamLen = teamID != NULL ? strlen(teamID) : 0;
    size_t capacity = 128 + PAD4(idLen) + PAD4(teamLen);

    uint8_t* blob = calloc(1, capacity);
    if (blob == NULL) {
        return NULL;
    }

    uint8_t* setLengthAt = blob + 4;
    uint8_t* requirementLengthAt;
    uint8_t* p = blob;

    // Requirements set containing a single designated requirement.
    p = put32be(p, CSMAGIC_REQUIREMENTS);
    p = put32be(p, 0); // patched below
    p = put32be(p, 1); // count
    p = put32be(p, CS_REQ_TYPE_DESIGNATED);
    p = put32be(p, 20); // offset of the requirement (set header + one entry)

    p = put32be(p, CSMAGIC_REQUIREMENT);
    requirementLengthAt = p;
    p = put32be(p, 0); // patched below
    p = put32be(p, 1); // kind

    p = put32be(p, OP_AND);
    p = put32be(p, OP_IDENT);
    p = put_data_field(p, (const uint8_t*)identifier, idLen);
    if (teamLen > 0) {
        p = put32be(p, OP_CERT_FIELD);
        p = put32be(p, CERT_SLOT_LEAF);
        p = put_data_field(p, (const uint8_t*)kSubjectOU, sizeof(kSubjectOU) - 1);
        p = put32be(p, MATCH_CONTAINS);
        p = put_data_field(p, (const uint8_t*)teamID, teamLen);
    } else {
        p = put32be(p, OP_ANCHOR_HASH);
        p = put32be(p, (uint32_t)CERT_SLOT_ANCHOR);
        p = put_data_field(p, identity->certSha1, sizeof(identity->certSha1));
    }

    size_t total = (size_t)(p - blob);
    write32be(setLengthAt, (uint32_t)total);
    write32be(requirementLengthAt, (uint32_t)(total - 20));
    *outLen = total;
    return blob;
}

static size_t code_directory_size(size_t ncode, size_t nspec, const SigMeta* meta) {
    size_t size = codeDirectorySize + strlen(meta->identifier) + 1;
    if (meta->teamID != NULL) {
        size += strlen(meta->teamID) + 1;
    }
    size += (nspec + ncode) * HASH_SIZE_32;
    return size;
}

static void build_code_directory(uint8_t* cd, const SigMeta* meta, size_t ncode, size_t nspec,
                                 uint32_t flags, const uint8_t* code, size_t codeSize,
                                 uint64_t execSegBase, uint64_t execSegLimit,
                                 uint64_t execSegFlags) {
    size_t idLen = strlen(meta->identifier) + 1;
    size_t teamLen = meta->teamID != NULL ? strlen(meta->teamID) + 1 : 0;
    size_t identOffset = codeDirectorySize;
    size_t teamOffset = meta->teamID != NULL ? identOffset + idLen : 0;
    size_t hashOffset = identOffset + idLen + teamLen + nspec * HASH_SIZE_32;

    CodeDirectory cdir = {
        .magic = CSMAGIC_CODEDIRECTORY,
        .length = (uint32_t)(hashOffset + ncode * HASH_SIZE_32),
        .version = 0x20400,
        .flags = flags,
        .hashOffset = (uint32_t)hashOffset,
        .identOffset = (uint32_t)identOffset,
        .nSpecialSlots = (uint32_t)nspec,
        .nCodeSlots = (uint32_t)ncode,
        .codeLimit = codeSize <= UINT32_MAX ? (uint32_t)codeSize : 0,
        .hashSize = HASH_SIZE_32,
        .hashType = CS_HASHTYPE_SHA256,
        .pageSize = PAGE_BITS,
        .teamOffset = (uint32_t)teamOffset,
        .codeLimit64 = codeSize > UINT32_MAX ? codeSize : 0,
        .execSegBase = execSegBase,
        .execSegLimit = execSegLimit,
        .execSegFlags = execSegFlags,
    };
    uint8_t* ptr = CodeDirectory_put(&cdir, cd);
    memcpy(ptr, meta->identifier, idLen);
    ptr += idLen;
    if (teamLen > 0) {
        memcpy(ptr, meta->teamID, teamLen);
    }

    // Special slot hashes cover the blobs the CodeDirectory cannot cover with
    // code pages: slot 2 holds the requirements, slot 5 the entitlements.
    if (meta->requirements != NULL) {
        sha256_digest(meta->requirements, meta->requirementsLen,
                      cd + hashOffset - 2 * HASH_SIZE_32);
    }
    if (meta->entitlements != NULL) {
        sha256_digest(meta->entitlements, meta->entitlementsLen,
                      cd + hashOffset - 5 * HASH_SIZE_32);
    }

    for (size_t page = 0; page < ncode; page++) {
        size_t offset = page * PAGE_SIZE;
        size_t remaining = codeSize - offset;
        size_t n = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;
        sha256_digest(code + offset, n, cd + hashOffset + page * HASH_SIZE_32);
    }
}

// Writes the SuperBlob (slot index + blobs) into out, which must have room for
// allocSize bytes. Returns the unpadded blob length.
static size_t assemble_superblob(uint8_t* out, const SigMeta* meta, const uint8_t* cd,
                                 size_t cdLen, const uint8_t* cms, size_t cmsLen,
                                 size_t allocSize) {
    size_t count = 1 + (meta->requirements != NULL) + (meta->entitlements != NULL) +
                   (cms != NULL ? 1 : 0);
    uint8_t* lengthAt = out + 4;
    uint8_t* index = out + superBlobSize;
    uint8_t* cursor = out + superBlobSize + count * blobSize;

    write32be(out, CSMAGIC_EMBEDDED_SIGNATURE);
    write32be(out + 4, 0); // patched below
    write32be(out + 8, (uint32_t)count);

#define ADD_SLOT(slot, data, len)                        \
    do {                                                 \
        write32be(index, (slot));                        \
        write32be(index + 4, (uint32_t)(cursor - out));  \
        index += 8;                                      \
        memcpy(cursor, (data), (len));                   \
        cursor += (len);                                 \
    } while (0)

    ADD_SLOT(CSSLOT_CODEDIRECTORY, cd, cdLen);
    if (meta->requirements != NULL) {
        ADD_SLOT(CSSLOT_REQUIREMENTS, meta->requirements, meta->requirementsLen);
    }
    if (meta->entitlements != NULL) {
        ADD_SLOT(CSSLOT_ENTITLEMENTS, meta->entitlements, meta->entitlementsLen);
    }
    if (cms != NULL) {
        ADD_SLOT(CSSLOT_SIGNATURESLOT, cms, cmsLen);
    }

#undef ADD_SLOT

    size_t total = (size_t)(cursor - out);
    write32be(lengthAt, (uint32_t)total);
    if (allocSize > total) {
        memset(cursor, 0, allocSize - total);
    }
    return total;
}

#ifndef ADHOC_SIGNER_WASM
static uint8_t* read_file(const char* path, size_t* sizeOut) {
    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "%s: failed to seek\n", path);
        fclose(file);
        return NULL;
    }

    long end = ftell(file);
    if (end < 0) {
        fprintf(stderr, "%s: failed to determine file size\n", path);
        fclose(file);
        return NULL;
    }
    rewind(file);

    uint8_t* data = malloc((size_t)end);
    if (data == NULL) {
        fprintf(stderr, "failed to allocate %ld bytes\n", end);
        fclose(file);
        return NULL;
    }

    if (fread(data, 1, (size_t)end, file) != (size_t)end) {
        fprintf(stderr, "%s: failed to read file\n", path);
        free(data);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *sizeOut = (size_t)end;
    return data;
}

static int write_file(const char* path, const uint8_t* data, size_t size, mode_t mode) {
    FILE* file = fopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        return -1;
    }

    if (fwrite(data, 1, size, file) != size) {
        fprintf(stderr, "%s: failed to write file\n", path);
        fclose(file);
        return -1;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "%s: failed to close file\n", path);
        return -1;
    }

    if (chmod(path, mode) != 0) {
        fprintf(stderr, "%s: failed to set permissions: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}
#endif

typedef struct {
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t filetype;
    size_t firstFileOffset;
    size_t linkeditCommandOffset;
    uint64_t linkeditFileSize;
    size_t codeSignatureCommandOffset;
    uint32_t oldSignatureOffset;
    uint32_t oldSignatureSize;
    uint64_t textSize;
    uint64_t textSegmentVmsize;
} MachOInfo;

static int name_equals(const char* fixed, const char* value) {
    return strncmp(fixed, value, 16) == 0;
}

static int parse_macho(const uint8_t* data, size_t size, MachOInfo* info) {
    if (size < sizeof(mach_header_64)) {
        fprintf(stderr, "input is too small to be a Mach-O executable\n");
        return -1;
    }

    if (read32le(data) != MH_MAGIC_64) {
        fprintf(stderr, "only 64-bit little-endian Mach-O files are supported\n");
        return -1;
    }

    memset(info, 0, sizeof(*info));
    info->filetype = read32le(data + 12);
    info->ncmds = read32le(data + 16);
    info->sizeofcmds = read32le(data + 20);
    info->firstFileOffset = size;

    size_t commandOffset = sizeof(mach_header_64);
    size_t commandsEnd = commandOffset + info->sizeofcmds;
    if (commandsEnd > size) {
        fprintf(stderr, "Mach-O load command table extends beyond the file\n");
        return -1;
    }

    for (uint32_t i = 0; i < info->ncmds; i++) {
        if (commandOffset + sizeof(load_command) > commandsEnd) {
            fprintf(stderr, "truncated Mach-O load command\n");
            return -1;
        }

        uint32_t cmd = read32le(data + commandOffset);
        uint32_t cmdsize = read32le(data + commandOffset + 4);
        if (cmdsize < sizeof(load_command) || commandOffset + cmdsize > commandsEnd) {
            fprintf(stderr, "invalid Mach-O load command size\n");
            return -1;
        }

        if (cmd == LC_SEGMENT_64) {
            if (cmdsize < sizeof(segment_command_64)) {
                fprintf(stderr, "invalid LC_SEGMENT_64 size\n");
                return -1;
            }

            const uint8_t* segment = data + commandOffset;
            const char* segname = (const char*)(segment + 8);
            uint64_t fileoff = read64le(segment + 40);
            uint64_t filesize = read64le(segment + 48);
            uint32_t nsects = read32le(segment + 64);

            if (filesize > 0 && fileoff > 0 && fileoff < info->firstFileOffset) {
                info->firstFileOffset = (size_t)fileoff;
            }

            if (name_equals(segname, "__LINKEDIT")) {
                info->linkeditCommandOffset = commandOffset;
                info->linkeditFileSize = filesize;
            }

            if (name_equals(segname, "__TEXT")) {
                info->textSegmentVmsize = read64le(segment + 32);
                size_t sectionOffset = commandOffset + sizeof(segment_command_64);
                for (uint32_t j = 0; j < nsects; j++) {
                    if (sectionOffset + sizeof(section_64) > commandOffset + cmdsize) {
                        fprintf(stderr, "invalid section table in __TEXT\n");
                        return -1;
                    }
                    const uint8_t* section = data + sectionOffset;
                    const char* sectname = (const char*)section;
                    const char* sectionSegname = (const char*)(section + 16);
                    uint32_t fileOffset = read32le(section + 48);
                    if (fileOffset > 0 && fileOffset < info->firstFileOffset) {
                        info->firstFileOffset = fileOffset;
                    }
                    if (name_equals(sectname, "__text") && name_equals(sectionSegname, "__TEXT")) {
                        info->textSize = read64le(section + 40);
                    }
                    sectionOffset += sizeof(section_64);
                }
            }
        } else if (cmd == LC_CODE_SIGNATURE) {
            if (cmdsize < sizeof(CodeSignCmd)) {
                fprintf(stderr, "invalid LC_CODE_SIGNATURE size\n");
                return -1;
            }
            info->codeSignatureCommandOffset = commandOffset;
            info->oldSignatureOffset = read32le(data + commandOffset + 8);
            info->oldSignatureSize = read32le(data + commandOffset + 12);
        }

        commandOffset += cmdsize;
    }

    if (info->filetype != MH_EXECUTE) {
        fprintf(stderr, "only Mach-O executable files are supported\n");
        return -1;
    }

    if (info->linkeditCommandOffset == 0) {
        fprintf(stderr, "missing __LINKEDIT segment\n");
        return -1;
    }

    return 0;
}

static int add_or_update_code_signature(uint8_t* data, size_t originalSize, size_t dataOffset,
                                        uint32_t signatureSize, MachOInfo* info) {
    size_t commandOffset = info->codeSignatureCommandOffset;
    if (commandOffset == 0) {
        commandOffset = sizeof(mach_header_64) + info->sizeofcmds;
        if (commandOffset + sizeof(CodeSignCmd) > info->firstFileOffset) {
            fprintf(stderr, "not enough header padding to add LC_CODE_SIGNATURE\n");
            return -1;
        }

        write32le(data + 16, info->ncmds + 1);
        write32le(data + 20, info->sizeofcmds + sizeof(CodeSignCmd));
        info->sizeofcmds += sizeof(CodeSignCmd);
        info->ncmds++;
    }

    write32le(data + commandOffset, LC_CODE_SIGNATURE);
    write32le(data + commandOffset + 4, sizeof(CodeSignCmd));
    write32le(data + commandOffset + 8, (uint32_t)dataOffset);
    write32le(data + commandOffset + 12, signatureSize);

    uint64_t oldSignedPayload = 0;
    if (info->oldSignatureOffset != 0) {
        oldSignedPayload = info->oldSignatureSize;
        if (info->oldSignatureOffset > originalSize) {
            fprintf(stderr, "existing code signature offset is outside the file\n");
            return -1;
        }
    }

    uint64_t newLinkeditFileSize = info->linkeditFileSize - oldSignedPayload;
    if (info->codeSignatureCommandOffset == 0) {
        newLinkeditFileSize += dataOffset - originalSize;
    }
    newLinkeditFileSize += signatureSize;
    write64le(data + info->linkeditCommandOffset + 48, newLinkeditFileSize);

    return 0;
}

static int sign_macho_data(const uint8_t* input, size_t inputSize, const char* identifier,
                           const SignOptions* options, uint8_t** outputOut,
                           size_t* outputSizeOut) {
    MachOInfo info;
    if (parse_macho(input, inputSize, &info) != 0) {
        return 1;
    }

    size_t codeSize = info.oldSignatureOffset != 0 ? info.oldSignatureOffset : inputSize;
    size_t dataOffset = align_up(codeSize, 16);

    SigMeta meta = {
        .identifier = identifier,
    };
    SignerIdentity identity = {0};
    int haveIdentity = 0;
    uint8_t* requirements = NULL;
    uint8_t* entitlements = NULL;
    uint8_t* cms = NULL;
    uint8_t* cd = NULL;
    uint8_t* output = NULL;
    size_t cmsLen = 0;
    int result = 1;

    if (options != NULL && (options->p12Path != NULL || options->p12Data != NULL)) {
        size_t p12Size = 0;
        uint8_t* ownedP12 = NULL;
        const uint8_t* p12 = options->p12Data;
        if (p12 != NULL) {
            p12Size = options->p12Size;
        }
#ifndef ADHOC_SIGNER_WASM
        else if (options->p12Path != NULL) {
            ownedP12 = read_file(options->p12Path, &p12Size);
            p12 = ownedP12;
        }
#endif
        if (p12 == NULL) {
            goto cleanup;
        }
        char error[256];
        const char* password = options->p12Pass != NULL ? options->p12Pass : "";
        if (identity_load_p12(&identity, p12, p12Size, password, error, sizeof(error)) != 0) {
            fprintf(stderr, "%s\n", error);
            free(ownedP12);
            goto cleanup;
        }
        free(ownedP12);
        haveIdentity = 1;

        // The team ID is only honored for Apple-issued certificates: the
        // kernel checks a CodeDirectory teamOffset against the signer and
        // rejects signatures where the certificate cannot be the team it
        // claims (e.g. a self-signed cert with an OU in the subject).
        if (options->teamID != NULL && options->teamID[0] != '\0') {
            if (identity.appleIssued) {
                meta.teamID = options->teamID;
            } else {
                fprintf(stderr,
                        "warning: ignoring --team-id, the signing certificate is not "
                        "Apple-issued\n");
            }
        } else if (identity.appleIssued && identity.teamIDLen > 0) {
            meta.teamID = identity.teamID;
        }

        size_t requirementsLen = 0;
        requirements = build_requirements_blob(identifier, &identity, meta.teamID,
                                               &requirementsLen);
        if (requirements == NULL) {
            fprintf(stderr, "failed to build requirements blob\n");
            goto cleanup;
        }
        meta.requirements = requirements;
        meta.requirementsLen = requirementsLen;
    }

    if (options != NULL && options->teamID != NULL && options->teamID[0] != '\0' &&
        !haveIdentity) {
        fprintf(stderr, "--team-id requires --p12\n");
        goto cleanup;
    }

    if (options != NULL &&
        (options->entitlementsPath != NULL || options->entitlementsData != NULL)) {
        size_t xmlSize = 0;
        uint8_t* ownedXml = NULL;
        const uint8_t* xml = options->entitlementsData;
        if (xml != NULL) {
            xmlSize = options->entitlementsSize;
        }
#ifndef ADHOC_SIGNER_WASM
        else if (options->entitlementsPath != NULL) {
            ownedXml = read_file(options->entitlementsPath, &xmlSize);
            xml = ownedXml;
        }
#endif
        if (xml == NULL) {
            goto cleanup;
        }
        size_t entitlementsLen = 0;
        entitlements = build_entitlements_blob(xml, xmlSize, &entitlementsLen);
        free(ownedXml);
        if (entitlements == NULL) {
            fprintf(stderr, "failed to build entitlements blob\n");
            goto cleanup;
        }
        meta.entitlements = entitlements;
        meta.entitlementsLen = entitlementsLen;
    }

    size_t ncode = (dataOffset + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t nspec = 0;
    if (meta.requirements != NULL) {
        nspec = 2;
    }
    if (meta.entitlements != NULL && nspec < 5) {
        nspec = 5;
    }

    size_t cdSize = code_directory_size(ncode, nspec, &meta);
    size_t slotCount = 1 + (meta.requirements != NULL) + (meta.entitlements != NULL) +
                       (haveIdentity ? 1 : 0);
    size_t signatureSize =
        superBlobSize + slotCount * blobSize + cdSize + meta.requirementsLen + meta.entitlementsLen;

    if (haveIdentity) {
        // The CMS blob size is not knowable before signing, but its final size ends up in
        // LC_CODE_SIGNATURE, which lives inside the hashed region. Sign a throwaway buffer
        // of the same length to measure the exact size, then reserve slack on top for the
        // small variation an ECDSA signature can have between two signings.
        uint8_t* scratch = calloc(1, cdSize);
        if (scratch == NULL) {
            fprintf(stderr, "failed to allocate %zu bytes\n", cdSize);
            goto cleanup;
        }
        uint8_t* trial = identity_sign_blob(&identity, scratch, cdSize, &cmsLen);
        free(scratch);
        if (trial == NULL) {
            fprintf(stderr, "failed to create CMS signature\n");
            goto cleanup;
        }
        free(trial);
        signatureSize += cmsLen + 32;
    }

    size_t signatureAllocSize = align_up(signatureSize, haveIdentity ? 16 : 8);
    size_t outputSize = dataOffset + signatureAllocSize;

    if (codeSize > UINT32_MAX || dataOffset > UINT32_MAX || signatureAllocSize > UINT32_MAX) {
        fprintf(stderr, "file is too large for this simple signer\n");
        goto cleanup;
    }

    output = calloc(1, outputSize);
    if (output == NULL) {
        fprintf(stderr, "failed to allocate %zu bytes\n", outputSize);
        goto cleanup;
    }

    memcpy(output, input, codeSize);
    if (add_or_update_code_signature(output, inputSize, dataOffset,
                                     (uint32_t)signatureAllocSize, &info) != 0) {
        goto cleanup;
    }

    // The load command above is part of the hashed region, so it must be written
    // before the page hashes are computed.
    cd = calloc(1, cdSize);
    if (cd == NULL) {
        fprintf(stderr, "failed to allocate %zu bytes\n", cdSize);
        goto cleanup;
    }
    uint32_t flags = haveIdentity ? 0 : 0x20002; // ad-hoc: CS_ADHOC | CS_LINKER_SIGNED
    build_code_directory(cd, &meta, ncode, nspec, flags, output, dataOffset, 0,
                         info.textSegmentVmsize, 1);

    if (haveIdentity) {
        cms = identity_sign_blob(&identity, cd, cdSize, &cmsLen);
        if (cms == NULL) {
            fprintf(stderr, "failed to create CMS signature\n");
            goto cleanup;
        }
    }

    size_t written =
        assemble_superblob(output + dataOffset, &meta, cd, cdSize, cms, cmsLen, signatureAllocSize);
    if (written > signatureAllocSize) {
        fprintf(stderr, "internal error: signature grew past reserved space\n");
        goto cleanup;
    }

    *outputOut = output;
    *outputSizeOut = outputSize;
    output = NULL;
    result = 0;

cleanup:
    free(requirements);
    free(entitlements);
    free(cms);
    free(cd);
    free(output);
    if (haveIdentity) {
        identity_free(&identity);
    }
    return result;
}

#ifdef ADHOC_SIGNER_WASM
WASM_EXPORT uint8_t* sign_macho_wasm_adhoc(const uint8_t* input, size_t inputSize,
                                     const char* identifier, size_t* outputSizeOut) {
    if (input == NULL || identifier == NULL || outputSizeOut == NULL) {
        return NULL;
    }

    uint8_t* output = NULL;
    size_t outputSize = 0;
    if (sign_macho_data(input, inputSize, identifier, NULL, &output, &outputSize) != 0) {
        *outputSizeOut = 0;
        return NULL;
    }

    *outputSizeOut = outputSize;
    return output;
}

WASM_EXPORT uint8_t* sign_macho_wasm_cert(
    const uint8_t* input, size_t inputSize, const char* identifier,
    const uint8_t* p12Data, size_t p12Size, const char* p12Pass,
    const char* teamID, const uint8_t* entitlementsData, size_t entitlementsSize,
    size_t* outputSizeOut) {
    if (input == NULL || identifier == NULL || p12Data == NULL || p12Size == 0 ||
        outputSizeOut == NULL || (entitlementsSize > 0 && entitlementsData == NULL)) {
        return NULL;
    }

    SignOptions options = {
        .p12Pass = p12Pass,
        .teamID = teamID,
        .p12Data = p12Data,
        .p12Size = p12Size,
        .entitlementsData = entitlementsData,
        .entitlementsSize = entitlementsSize,
    };
    uint8_t* output = NULL;
    size_t outputSize = 0;
    if (sign_macho_data(input, inputSize, identifier, &options, &output, &outputSize) != 0) {
        *outputSizeOut = 0;
        return NULL;
    }

    *outputSizeOut = outputSize;
    return output;
}
#endif

#ifndef ADHOC_SIGNER_WASM
static int sign_macho(const char* inputPath, const char* outputPath, const char* identifier,
                      const SignOptions* options) {
    size_t inputSize = 0;
    uint8_t* input = read_file(inputPath, &inputSize);
    if (input == NULL) {
        return 1;
    }

    struct stat inputStat;
    if (stat(inputPath, &inputStat) != 0) {
        fprintf(stderr, "%s: %s\n", inputPath, strerror(errno));
        free(input);
        return 1;
    }

    uint8_t* output = NULL;
    size_t outputSize = 0;
    if (sign_macho_data(input, inputSize, identifier, options, &output, &outputSize) != 0) {
        free(input);
        return 1;
    }

    int result = write_file(outputPath, output, outputSize, inputStat.st_mode & 0777);
    free(output);
    free(input);
    return result == 0 ? 0 : 1;
}

static void usage(const char* program) {
    fprintf(stderr,
            "Usage: %s <input_macho> <identifier> <output_macho> [options]\n"
            "\n"
            "Creates a signed 64-bit Mach-O executable. Without --p12 the signature is\n"
            "ad-hoc: page hashes only, no certificate or identity.\n"
            "\n"
            "Options:\n"
            "  --p12 <file>          sign with the certificate and key stored in a\n"
            "                        PKCS#12 file (adds requirements and a CMS signature)\n"
            "  --p12-pass <pass>     password for the PKCS#12 file (default: empty)\n"
            "  --team-id <id>        override the team ID (default: first OU in the\n"
            "                        certificate subject; requires --p12)\n"
            "  --entitlements <file> embed an entitlements plist (XML)\n",
            program);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    SignOptions options = {0};
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--p12") == 0 && i + 1 < argc) {
            options.p12Path = argv[++i];
        } else if (strcmp(argv[i], "--p12-pass") == 0 && i + 1 < argc) {
            options.p12Pass = argv[++i];
        } else if (strcmp(argv[i], "--team-id") == 0 && i + 1 < argc) {
            options.teamID = argv[++i];
        } else if (strcmp(argv[i], "--entitlements") == 0 && i + 1 < argc) {
            options.entitlementsPath = argv[++i];
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    return sign_macho(argv[1], argv[3], argv[2], &options);
}
#endif
