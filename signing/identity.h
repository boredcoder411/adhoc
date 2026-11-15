#pragma once

#include <stddef.h>
#include <stdint.h>

// A signing identity loaded from a PKCS#12 file: certificate, private key,
// and the certificate chain used to build the CMS signature.
typedef struct {
    void* cert;   /* X509* */
    void* key;    /* EVP_PKEY* */
    void* chain;  /* STACK_OF(X509)* */
    char teamID[32];
    size_t teamIDLen;
    // Only Apple-issued certificates have a real team ID: the kernel checks a
    // CodeDirectory teamOffset against the signer, and rejects it unless the
    // certificate chains to Apple. Self-signed certs must not set teamOffset.
    int appleIssued;
    uint8_t certSha1[20];  // used by the designated requirement fallback
} SignerIdentity;

// Parses PKCS#12 data. Returns 0 on success, -1 on failure with a message in error.
int identity_load_p12(SignerIdentity* identity, const uint8_t* data, size_t size,
                      const char* password, char* error, size_t errorSize);

// Returns 1 when the leaf certificate is self-signed or one of the chain
// certificates issued it. A leaf-only Apple-issued identity returns 0.
int identity_has_issuer(const SignerIdentity* identity);

// Completes the chain for an Apple-issued identity: if no chain certificate
// issued the leaf, adds the matching embedded WWDR intermediate, then appends
// the Apple root that issued a chain member (unless already present).
// Returns 0 when the identity has an issuer, -1 otherwise.
int identity_complete_apple_chain(SignerIdentity* identity);

void identity_free(SignerIdentity* identity);

// Signs data (typically the CodeDirectory) with the identity's key as a detached
// CMS/PKCS#7 signature. Returns a malloc'd blob (CSMAGIC_BLOBWRAPPER header
// followed by the DER-encoded CMS structure), or NULL on failure.
uint8_t* identity_sign_blob(const SignerIdentity* identity, const uint8_t* data,
                            size_t size, size_t* outSize);
