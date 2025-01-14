#include <stdio.h>
#include "signing/constants.h"

void Debug_CodeDirectory(CodeDirectory* cdir) {
    // Show CodeDirectory information
    printf("CodeDirectory: %d\n", cdir->magic);
    printf("Length: %d\n", cdir->length);
    printf("Version: %d\n", cdir->version);
    printf("Flags: %d\n", cdir->flags);
    printf("Hash Offset: %d\n", cdir->hashOffset);
    printf("Identifier Offset: %d\n", cdir->identOffset);
    printf("Number of Special Slots: %d\n", cdir->nSpecialSlots);
    printf("Number of Code Slots: %d\n", cdir->nCodeSlots);
    printf("Code Limit: %d\n", cdir->codeLimit);
    printf("Hash Size: %d\n", cdir->hashSize);
    printf("Hash Type: %d\n", cdir->hashType);
    printf("Page Size: %d\n", cdir->pageSize);
    printf("Exec Segment Base: %llu\n", cdir->execSegBase);
    printf("Exec Segment Limit: %llu\n", cdir->execSegLimit);
    printf("Exec Segment Flags: %llu\n", cdir->execSegFlags);
}
