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

static uint8_t* Blob_put(const Blob* b, uint8_t* out) {
    out = put32be(out, b->typ);
    out = put32be(out, b->offset);
    return out;
}

static uint8_t* SuperBlob_put(const SuperBlob* sb, uint8_t* out) {
    out = put32be(out, sb->magic);
    out = put32be(out, sb->length);
    out = put32be(out, sb->count);
    return out;
}

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

static size_t calculate_signature_size(size_t codeSize, const char* identifier) {
    size_t nhashes = (codeSize + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t idOffset = codeDirectorySize;
    size_t hashOffset = idOffset + strlen(identifier) + 1;
    size_t codeDirSize = hashOffset + nhashes * HASH_SIZE_32;
    return superBlobSize + blobSize + codeDirSize;
}

static void sign_buffer(const SignArgs* args) {
    size_t nhashes = (args->codeSize + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t idOffset = codeDirectorySize;
    size_t hashOffset = idOffset + strlen(args->identifier) + 1;
    size_t totalSize = calculate_signature_size(args->codeSize, args->identifier);

    SuperBlob sb = {
        .magic = CSMAGIC_EMBEDDED_SIGNATURE,
        .length = (uint32_t)totalSize,
        .count = 1,
    };

    uint8_t* ptr = args->output;
    ptr = SuperBlob_put(&sb, ptr);

    Blob blob = {
        .typ = CSSLOT_CODEDIRECTORY,
        .offset = (uint32_t)(superBlobSize + blobSize),
    };
    ptr = Blob_put(&blob, ptr);

    CodeDirectory cdir = {
        .magic = CSMAGIC_CODEDIRECTORY,
        .length = (uint32_t)(totalSize - (superBlobSize + blobSize)),
        .version = 0x20400,
        .flags = 0x20002,
        .hashOffset = (uint32_t)hashOffset,
        .identOffset = (uint32_t)idOffset,
        .nSpecialSlots = 0,
        .nCodeSlots = (uint32_t)nhashes,
        .codeLimit = args->codeSize <= UINT32_MAX ? (uint32_t)args->codeSize : 0,
        .hashSize = HASH_SIZE_32,
        .hashType = CS_HASHTYPE_SHA256,
        .pageSize = PAGE_BITS,
        .codeLimit64 = args->codeSize > UINT32_MAX ? args->codeSize : 0,
        .execSegBase = args->execSegBase,
        .execSegLimit = args->execSegLimit,
        .execSegFlags = args->isMain ? CS_EXECSEG_MAIN_BINARY : 0,
    };
    ptr = CodeDirectory_put(&cdir, ptr);

    size_t idLen = strlen(args->identifier) + 1;
    memcpy(ptr, args->identifier, idLen);
    ptr += idLen;

    for (size_t page = 0; page < nhashes; page++) {
        size_t offset = page * PAGE_SIZE;
        size_t remaining = args->codeSize - offset;
        size_t n = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;
        SHA256(args->code + offset, n, ptr);
        ptr += HASH_SIZE_32;
    }
}

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

static int sign_macho(const char* inputPath, const char* outputPath, const char* identifier) {
    size_t inputSize = 0;
    uint8_t* input = read_file(inputPath, &inputSize);
    if (input == NULL) {
        return 1;
    }

    MachOInfo info;
    if (parse_macho(input, inputSize, &info) != 0) {
        free(input);
        return 1;
    }

    struct stat inputStat;
    if (stat(inputPath, &inputStat) != 0) {
        fprintf(stderr, "%s: %s\n", inputPath, strerror(errno));
        free(input);
        return 1;
    }

    size_t codeSize = info.oldSignatureOffset != 0 ? info.oldSignatureOffset : inputSize;
    size_t dataOffset = align_up(codeSize, 16);
    size_t signatureSize = calculate_signature_size(dataOffset, identifier);
    size_t signatureAllocSize = align_up(signatureSize, 8);
    size_t outputSize = dataOffset + signatureAllocSize;

    if (codeSize > UINT32_MAX || dataOffset > UINT32_MAX || signatureAllocSize > UINT32_MAX) {
        fprintf(stderr, "file is too large for this simple signer\n");
        free(input);
        return 1;
    }

    uint8_t* output = calloc(1, outputSize);
    if (output == NULL) {
        fprintf(stderr, "failed to allocate %zu bytes\n", outputSize);
        free(input);
        return 1;
    }

    memcpy(output, input, codeSize);
    if (add_or_update_code_signature(output, inputSize, dataOffset,
                                     (uint32_t)signatureAllocSize, &info) != 0) {
        free(output);
        free(input);
        return 1;
    }

    SignArgs args = {
        .output = output + dataOffset,
        .code = output,
        .identifier = identifier,
        .codeSize = dataOffset,
        .execSegBase = 0,
        .execSegLimit = info.textSize,
        .isMain = 1,
    };
    sign_buffer(&args);

    int result = write_file(outputPath, output, outputSize, inputStat.st_mode & 0777);
    free(output);
    free(input);
    return result == 0 ? 0 : 1;
}

static void usage(const char* program) {
    fprintf(stderr, "Usage: %s <input_macho> <identifier> <output_macho>\n", program);
    fprintf(stderr, "Creates an ad-hoc signed 64-bit Mach-O executable.\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage(argv[0]);
        return 1;
    }

    return sign_macho(argv[1], argv[3], argv[2]);
}
