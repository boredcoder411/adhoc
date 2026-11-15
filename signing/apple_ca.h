#pragma once

#include <stddef.h>

// Apple's public WWDR intermediate and root certificates, as PEM. They are used
// to complete the chain for Apple-issued identities whose PKCS#12 contains only
// the leaf certificate.
extern const char* const appleCAIntermediatePEMs[];
extern const size_t appleCAIntermediatePEMCount;
extern const char* const appleCARootPEMs[];
extern const size_t appleCARootPEMCount;
