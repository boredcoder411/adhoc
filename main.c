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
#include <openssl/sha.h>
#include <dirent.h>

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

    if (args->textOffset > 0) {
        fseek(args->dataFile, args->textOffset, SEEK_SET);
    }

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

    uint8_t buffer[PAGE_SIZE];
    memset(buffer, 0, PAGE_SIZE);
    SHA256_CTX shaCtx;
    size_t readBytes = 0;
    size_t pageIndex = 0;
    while ((readBytes = fread(buffer, 1, PAGE_SIZE, args->dataFile)) > 0) {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256_Init(&shaCtx);
        SHA256_Update(&shaCtx, buffer, PAGE_SIZE);
        SHA256_Final(hash, &shaCtx);

        printf("Page %zu hash: ", pageIndex);
        for (size_t i = 0; i < HASH_SIZE_32; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");

        memcpy(ptr, hash, HASH_SIZE_32);
        ptr += HASH_SIZE_32;
        pageIndex++;
        
        memset(buffer, 0, PAGE_SIZE);
    }

    if (ferror(args->dataFile)) {
        perror("Error reading file");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <app_path> <identifier> [text_offset] [text_size]\n", argv[0]);
        fprintf(stderr, "  text_offset: Offset in the file to start hashing from (in hex, e.g. 0x1000)\n");
        fprintf(stderr, "  text_size: Size of the section to hash (in hex, e.g. 0x5000)\n");
        return 1;
    }

    const char* appPath = argv[1];
    const char* identifier = argv[2];
    
    size_t textOffset = 0;
    size_t textSize = 0;
    
    if (argc >= 4) {
        textOffset = strtoul(argv[3], NULL, 0);
    }
    
    if (argc >= 5) {
        textSize = strtoul(argv[4], NULL, 0);
    }

    SignArgs args = {
        .output = NULL,
        .dataFile = NULL,
        .identifier = identifier,
        .codeSize = 0,
        .textOffset = textOffset,
        .textSize = textSize,
        .isMain = 1
    };

    FILE* dataFile = fopen(appPath, "rb");
    if (dataFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    args.dataFile = dataFile;

    fseek(dataFile, 0, SEEK_END);
    size_t fileSize = ftell(dataFile);
    rewind(dataFile);
    
    if (args.textSize == 0) {
        args.textSize = fileSize - args.textOffset;
    }
    
    args.codeSize = args.textSize;
    
    size_t totalSize = CalculateSize(args.codeSize, args.identifier);
    args.output = malloc(totalSize);
    if (args.output == NULL) {
        perror("Error allocating memory");
        return 1;
    }

    Sign(&args);

    FILE* outputFile = fopen("signature", "wb");
    if (outputFile == NULL) {
        perror("Error opening output file");
        return 1;
    }

    fwrite(args.output, 1, totalSize, outputFile);

    fclose(outputFile);
    fclose(dataFile);
    free(args.output);

    return 0;
}

