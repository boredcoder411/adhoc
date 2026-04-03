/*
 * ALL THIS CODE IS A PORT TO C FROM THE GO LINKER.
 * ORIGINAL CAN BE FOUND HERE: https://tip.golang.org/src/cmd/internal/codesign/codesign.go?m=text
 * PARTS OF THIS CODE WERE MODIFIED TO COMPENSATE FOR
 * THE C LANGUAGE'S LACK OF OOP FEATURES
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <openssl/sha.h>

#include "macho/constants.h"
#include "signing/constants.h"

uint8_t* put8(uint8_t* out, uint8_t value) {
    *out++ = value;
    return out;
}

uint8_t* put32be(uint8_t* out, uint32_t value) {
    *out++ = (value >> 24) & 0xFF;
    *out++ = (value >> 16) & 0xFF;
    *out++ = (value >> 8) & 0xFF;
    *out++ = value & 0xFF;
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
    out = put32be(out, b->typ);
    out = put32be(out, b->offset);
    return out;
}

uint8_t* SuperBlob_put(SuperBlob* sb, uint8_t* out) {
    out = put32be(out, sb->magic);
    out = put32be(out, sb->length);
    out = put32be(out, sb->count);
    return out;
}

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

size_t CalculateSize(size_t codeSize, const char* identifier) {
    size_t nhashes = (codeSize + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t idOffset = codeDirectorySize;
    size_t hashOffset = idOffset + strlen(identifier) + 1;
    size_t codeDirSize = hashOffset + nhashes * HASH_SIZE_32;
    return superBlobSize + blobSize + codeDirSize;
}

void Sign(SignArgs* args) {
    size_t nhashes = (args->codeSize + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t idOffset = codeDirectorySize;
    size_t hashOffset = idOffset + strlen(args->identifier) + 1;
    size_t totalSize = CalculateSize(args->codeSize, args->identifier);

    SuperBlob sb = {
        .magic = CSMAGIC_EMBEDDED_SIGNATURE,
        .length = (uint32_t)totalSize,
        .count = 1
    };
    uint8_t* ptr = args->output;
    ptr = SuperBlob_put(&sb, ptr);

    Blob blob = {
        .typ = CSSLOT_CODEDIRECTORY,
        .offset = (uint32_t)(superBlobSize + blobSize)
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
        .codeLimit = (uint32_t)args->codeSize,
        .hashSize = HASH_SIZE_32,
        .hashType = CS_HASHTYPE_SHA256,
        .pageSize = PAGE_BITS,
        .execSegBase = args->textOffset,
        .execSegLimit = args->textSize,
        .execSegFlags = args->isMain ? CS_EXECSEG_MAIN_BINARY : 0
    };
    ptr = CodeDirectory_put(&cdir, ptr);

    size_t idLen = strlen(args->identifier) + 1;
    memcpy(ptr, args->identifier, idLen);
    ptr += idLen;

    SHA256_CTX shaCtx;
    size_t pageIndex = 0;
    while (pageIndex < nhashes) {
        uint8_t block[PAGE_SIZE];
        memset(block, 0, sizeof(block));

        size_t start = args->textOffset + pageIndex * PAGE_SIZE;
        size_t remaining = args->codeSize > pageIndex * PAGE_SIZE
            ? args->codeSize - pageIndex * PAGE_SIZE
            : 0;
        size_t toCopy = remaining > PAGE_SIZE ? PAGE_SIZE : remaining;
        if (toCopy > 0) {
            memcpy(block, args->data + start, toCopy);
        }

        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256_Init(&shaCtx);
        SHA256_Update(&shaCtx, block, PAGE_SIZE);
        SHA256_Final(hash, &shaCtx);

        memcpy(ptr, hash, HASH_SIZE_32);
        ptr += HASH_SIZE_32;
        pageIndex++;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <mach_o_path> <identifier> [text_offset] [text_size]\n", argv[0]);
        return 1;
    }

    const char* appPath = argv[1];
    const char* identifier = argv[2];

    size_t textOffset = 0;
    size_t textSize = 0;
    if (argc >= 4) {
        textOffset = strtoull(argv[3], NULL, 0);
    }
    if (argc >= 5) {
        textSize = strtoull(argv[4], NULL, 0);
    }

    FILE* dataFile = fopen(appPath, "rb");
    if (dataFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    if (fseek(dataFile, 0, SEEK_END) != 0) {
        perror("Error seeking file");
        fclose(dataFile);
        return 1;
    }
    long fileSizeLong = ftell(dataFile);
    if (fileSizeLong < 0) {
        perror("Error reading file size");
        fclose(dataFile);
        return 1;
    }
    size_t fileSize = (size_t)fileSizeLong;
    rewind(dataFile);

    uint8_t* fileData = malloc(fileSize);
    if (fileData == NULL) {
        perror("Error allocating memory");
        fclose(dataFile);
        return 1;
    }
    if (fread(fileData, 1, fileSize, dataFile) != fileSize) {
        perror("Error reading file");
        free(fileData);
        fclose(dataFile);
        return 1;
    }
    fclose(dataFile);

    if (fileSize < sizeof(mach_header_64)) {
        fprintf(stderr, "File too small to be a Mach-O binary\n");
        free(fileData);
        return 1;
    }

    uint32_t magic = *(uint32_t*)fileData;
    int is64 = (magic == MH_MAGIC_64);
    if (!(magic == MH_MAGIC || magic == MH_MAGIC_64)) {
        fprintf(stderr, "Unsupported Mach-O magic 0x%x (only little-endian Mach-O is supported)\n", magic);
        free(fileData);
        return 1;
    }

    uint32_t ncmds;
    uint32_t sizeofcmds;
    size_t headerSize = is64 ? sizeof(mach_header_64) : sizeof(mach_header);
    if (is64) {
        mach_header_64* hdr = (mach_header_64*)fileData;
        ncmds = hdr->ncmds;
        sizeofcmds = hdr->sizeofcmds;
    } else {
        mach_header* hdr = (mach_header*)fileData;
        ncmds = hdr->ncmds;
        sizeofcmds = hdr->sizeofcmds;
    }

    size_t loadStart = headerSize;
    size_t loadEnd = loadStart + sizeofcmds;
    if (loadEnd > fileSize) {
        fprintf(stderr, "Corrupt Mach-O: load commands extend past end of file\n");
        free(fileData);
        return 1;
    }

    CodeSignCmd* csCmd = NULL;
    size_t minDataFileOff = SIZE_MAX;
    size_t off = loadStart;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + sizeof(load_command) > fileSize) {
            fprintf(stderr, "Corrupt Mach-O: invalid load command table\n");
            free(fileData);
            return 1;
        }
        load_command* lc = (load_command*)(fileData + off);
        if (lc->cmdsize < sizeof(load_command) || off + lc->cmdsize > fileSize) {
            fprintf(stderr, "Corrupt Mach-O: invalid load command size\n");
            free(fileData);
            return 1;
        }

        if (lc->cmd == LC_CODE_SIGNATURE && lc->cmdsize >= sizeof(CodeSignCmd)) {
            csCmd = (CodeSignCmd*)(fileData + off);
        }
        if (lc->cmd == LC_SEGMENT && lc->cmdsize >= sizeof(segment_command)) {
            segment_command* seg = (segment_command*)(fileData + off);
            if (seg->fileoff > 0 && seg->fileoff < minDataFileOff) {
                minDataFileOff = seg->fileoff;
            }
        }
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(segment_command_64)) {
            segment_command_64* seg = (segment_command_64*)(fileData + off);
            if (seg->fileoff > 0 && seg->fileoff < minDataFileOff) {
                minDataFileOff = (size_t)seg->fileoff;
            }
        }

        off += lc->cmdsize;
    }

    if (off != loadEnd) {
        fprintf(stderr, "Corrupt Mach-O: load command table size mismatch\n");
        free(fileData);
        return 1;
    }

    size_t codeLimit = fileSize;
    if (csCmd != NULL && csCmd->dataOffset > 0 && csCmd->dataOffset <= fileSize) {
        codeLimit = csCmd->dataOffset;
    }

    if (textOffset > codeLimit) {
        fprintf(stderr, "text_offset is larger than code size\n");
        free(fileData);
        return 1;
    }

    if (textSize == 0) {
        textSize = codeLimit - textOffset;
    }
    if (textOffset + textSize > codeLimit) {
        fprintf(stderr, "text_offset + text_size exceeds code area\n");
        free(fileData);
        return 1;
    }

    if (csCmd == NULL) {
        if (minDataFileOff == SIZE_MAX) {
            fprintf(stderr, "Unable to determine available header space for LC_CODE_SIGNATURE\n");
            free(fileData);
            return 1;
        }
        if (loadEnd + sizeof(CodeSignCmd) > minDataFileOff) {
            fprintf(stderr, "No room for LC_CODE_SIGNATURE load command (build with -headerpad)\n");
            free(fileData);
            return 1;
        }
    }

    SignArgs signArgs = {
        .output = NULL,
        .data = fileData,
        .identifier = identifier,
        .codeSize = textSize,
        .textOffset = textOffset,
        .textSize = textSize,
        .isMain = 1
    };

    size_t sigSize = CalculateSize(signArgs.codeSize, signArgs.identifier);
    signArgs.output = malloc(sigSize);
    if (signArgs.output == NULL) {
        perror("Error allocating signature");
        free(fileData);
        return 1;
    }
    Sign(&signArgs);

    size_t newDataOff = codeLimit;
    size_t newFileSize = newDataOff + sigSize;
    uint8_t* newFile = malloc(newFileSize);
    if (newFile == NULL) {
        perror("Error allocating output file");
        free(signArgs.output);
        free(fileData);
        return 1;
    }

    memcpy(newFile, fileData, newDataOff);
    memcpy(newFile + newDataOff, signArgs.output, sigSize);

    if (is64) {
        mach_header_64* hdr = (mach_header_64*)newFile;
        if (csCmd == NULL) {
            size_t csOff = headerSize + hdr->sizeofcmds;
            CodeSignCmd* newCmd = (CodeSignCmd*)(newFile + csOff);
            newCmd->cmd = LC_CODE_SIGNATURE;
            newCmd->cmdsize = sizeof(CodeSignCmd);
            newCmd->dataOffset = (uint32_t)newDataOff;
            newCmd->dataSize = (uint32_t)sigSize;
            hdr->ncmds += 1;
            hdr->sizeofcmds += sizeof(CodeSignCmd);
        } else {
            size_t csOff = (uint8_t*)csCmd - fileData;
            CodeSignCmd* newCmd = (CodeSignCmd*)(newFile + csOff);
            newCmd->dataOffset = (uint32_t)newDataOff;
            newCmd->dataSize = (uint32_t)sigSize;
        }
    } else {
        mach_header* hdr = (mach_header*)newFile;
        if (csCmd == NULL) {
            size_t csOff = headerSize + hdr->sizeofcmds;
            CodeSignCmd* newCmd = (CodeSignCmd*)(newFile + csOff);
            newCmd->cmd = LC_CODE_SIGNATURE;
            newCmd->cmdsize = sizeof(CodeSignCmd);
            newCmd->dataOffset = (uint32_t)newDataOff;
            newCmd->dataSize = (uint32_t)sigSize;
            hdr->ncmds += 1;
            hdr->sizeofcmds += sizeof(CodeSignCmd);
        } else {
            size_t csOff = (uint8_t*)csCmd - fileData;
            CodeSignCmd* newCmd = (CodeSignCmd*)(newFile + csOff);
            newCmd->dataOffset = (uint32_t)newDataOff;
            newCmd->dataSize = (uint32_t)sigSize;
        }
    }

    FILE* outputFile = fopen(appPath, "wb");
    if (outputFile == NULL) {
        perror("Error opening output file");
        free(newFile);
        free(signArgs.output);
        free(fileData);
        return 1;
    }

    if (fwrite(newFile, 1, newFileSize, outputFile) != newFileSize) {
        perror("Error writing output file");
        fclose(outputFile);
        free(newFile);
        free(signArgs.output);
        free(fileData);
        return 1;
    }

    fclose(outputFile);
    free(newFile);
    free(signArgs.output);
    free(fileData);

    printf("Embedded ad-hoc signature in %s (offset=%zu size=%zu)\n", appPath, newDataOff, sigSize);
    return 0;
}
