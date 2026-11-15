#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "identity.h"
#include "apple_ca.h"

#define CSMAGIC_BLOBWRAPPER 0xfade0b01

static void set_error(char* error, size_t errorSize, const char* what) {
    if (error == NULL || errorSize == 0) {
        return;
    }
    unsigned long code = ERR_get_error();
    if (code != 0) {
        snprintf(error, errorSize, "%s: %s", what, ERR_error_string(code, NULL));
    } else {
        snprintf(error, errorSize, "%s", what);
    }
}

static void write32be(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

// Certificates exported by older tools use RC2-40-CBC, which OpenSSL 3 moved to
// the legacy provider. Load it on demand so those PKCS#12 files keep working
// without forcing every caller to pay for it up front. Providers loaded here are
// intentionally never unloaded: the parsed key and certificate may still refer
// to algorithms registered by the provider.
static int load_legacy_provider(void) {
    static int available = -1;
    if (available >= 0) {
        return available;
    }
    ERR_clear_error();
    available = OSSL_PROVIDER_load(NULL, "legacy") != NULL;
    return available;
}

static int p12_parse(PKCS12* p12, const char* password, SignerIdentity* identity) {
    return PKCS12_parse(p12, password, (EVP_PKEY**)&identity->key, (X509**)&identity->cert,
                        (STACK_OF(X509)**)&identity->chain);
}

static int is_wrong_password(unsigned long code) {
    return ERR_GET_LIB(code) == ERR_LIB_PKCS12 &&
           ERR_GET_REASON(code) == PKCS12_R_MAC_VERIFY_FAILURE;
}

int identity_load_p12(SignerIdentity* identity, const uint8_t* data, size_t size,
                      const char* password, char* error, size_t errorSize) {
    memset(identity, 0, sizeof(*identity));

    const unsigned char* cursor = data;
    PKCS12* p12 = d2i_PKCS12(NULL, &cursor, (long)size);
    if (p12 == NULL) {
        set_error(error, errorSize, "invalid PKCS#12 data");
        return -1;
    }

    ERR_clear_error();
    if (p12_parse(p12, password, identity) != 1) {
        unsigned long code = ERR_peek_last_error();
        if (is_wrong_password(code)) {
            snprintf(error, errorSize, "failed to parse PKCS#12: wrong password");
            PKCS12_free(p12);
            return -1;
        }

        // Most likely an unsupported legacy cipher such as RC2-40-CBC. Retry
        // with the legacy provider enabled before giving up.
        identity_free(identity);
        ERR_clear_error();
        if (!load_legacy_provider()) {
            set_error(error, errorSize,
                      "failed to parse PKCS#12 (unsupported encryption; this OpenSSL "
                      "build cannot load the legacy provider)");
            PKCS12_free(p12);
            return -1;
        }

        if (p12_parse(p12, password, identity) != 1) {
            code = ERR_peek_last_error();
            if (is_wrong_password(code)) {
                snprintf(error, errorSize, "failed to parse PKCS#12: wrong password");
            } else {
                set_error(error, errorSize, "failed to parse PKCS#12");
            }
            identity_free(identity);
            PKCS12_free(p12);
            return -1;
        }
    }
    PKCS12_free(p12);

    if (identity->cert == NULL || identity->key == NULL) {
        set_error(error, errorSize, "PKCS#12 must contain both a certificate and a private key");
        identity_free(identity);
        return -1;
    }

    // The team ID is the first OU in the certificate's subject. It is only
    // meaningful when the certificate is Apple-issued, but I use a self signed cert
    // manually trusted via the security cli tool in macos
    const STACK_OF(X509_EXTENSION)* extensions = X509_get0_extensions((X509*)identity->cert);
    for (int i = 0; extensions != NULL && i < sk_X509_EXTENSION_num(extensions); i++) {
        X509_EXTENSION* extension = sk_X509_EXTENSION_value(extensions, i);
        char oid[64];
        if (OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(extension), 1) > 0 &&
            strncmp(oid, "1.2.840.113635.100.", 19) == 0) {
            identity->appleIssued = 1;
            break;
        }
    }

    char teamID[64];
    int length = X509_NAME_get_text_by_NID(X509_get_subject_name((X509*)identity->cert),
                                           NID_organizationalUnitName, teamID, (int)sizeof(teamID));
    if (length > 0) {
        strncpy(identity->teamID, teamID, sizeof(identity->teamID) - 1);
        identity->teamIDLen = strlen(identity->teamID);
    }

    X509_digest((X509*)identity->cert, EVP_sha1(), identity->certSha1, NULL);
    return 0;
}

int identity_has_issuer(const SignerIdentity* identity) {
    X509* certificate = (X509*)identity->cert;
    if (certificate == NULL) {
        return 0;
    }
    // A self-signed certificate is its own issuer and needs no chain entry.
    if (X509_check_issued(certificate, certificate) == X509_V_OK) {
        return 1;
    }
    STACK_OF(X509)* chain = (STACK_OF(X509)*)identity->chain;
    for (int i = 0; chain != NULL && i < sk_X509_num(chain); i++) {
        if (X509_check_issued(sk_X509_value(chain, i), certificate) == X509_V_OK) {
            return 1;
        }
    }
    return 0;
}

static X509* parse_pem_certificate(const char* pem) {
    BIO* bio = BIO_new_mem_buf(pem, -1);
    if (bio == NULL) {
        return NULL;
    }
    X509* certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return certificate;
}

static int chain_contains_certificate(STACK_OF(X509)* chain, X509* certificate) {
    for (int i = 0; chain != NULL && i < sk_X509_num(chain); i++) {
        if (X509_cmp(sk_X509_value(chain, i), certificate) == 0) {
            return 1;
        }
    }
    return 0;
}

static int append_chain_certificate(SignerIdentity* identity, X509* certificate) {
    if (identity->chain == NULL) {
        identity->chain = sk_X509_new_null();
    }
    if (identity->chain == NULL ||
        sk_X509_push((STACK_OF(X509)*)identity->chain, certificate) == 0) {
        return -1;
    }
    return 0;
}

int identity_complete_apple_chain(SignerIdentity* identity) {
    X509* leaf = (X509*)identity->cert;
    if (leaf == NULL) {
        return -1;
    }

    if (!identity_has_issuer(identity)) {
        for (size_t i = 0; i < appleCAIntermediatePEMCount; i++) {
            X509* candidate = parse_pem_certificate(appleCAIntermediatePEMs[i]);
            if (candidate == NULL) {
                continue;
            }
            if (X509_check_issued(candidate, leaf) != X509_V_OK) {
                X509_free(candidate);
                continue;
            }
            if (append_chain_certificate(identity, candidate) != 0) {
                X509_free(candidate);
                return -1;
            }
            break;
        }
        if (!identity_has_issuer(identity)) {
            return -1;
        }
    }

    // Match Apple's codesign output by also embedding the root that issued a
    // member of the chain. Some verifiers stop at the system trust store, but
    // including it keeps the CMS self-contained.
    for (size_t i = 0; i < appleCARootPEMCount; i++) {
        X509* root = parse_pem_certificate(appleCARootPEMs[i]);
        if (root == NULL) {
            continue;
        }

        int issuedChainMember = 0;
        STACK_OF(X509)* chain = (STACK_OF(X509)*)identity->chain;
        for (int j = 0; chain != NULL && j < sk_X509_num(chain); j++) {
            if (X509_check_issued(root, sk_X509_value(chain, j)) == X509_V_OK) {
                issuedChainMember = 1;
                break;
            }
        }

        if (!issuedChainMember || chain_contains_certificate(chain, root)) {
            X509_free(root);
            continue;
        }
        if (append_chain_certificate(identity, root) != 0) {
            X509_free(root);
            return -1;
        }
    }
    return 0;
}

void identity_free(SignerIdentity* identity) {
    if (identity->cert != NULL) {
        X509_free((X509*)identity->cert);
    }
    if (identity->key != NULL) {
        EVP_PKEY_free((EVP_PKEY*)identity->key);
    }
    if (identity->chain != NULL) {
        sk_X509_pop_free((STACK_OF(X509)*)identity->chain, X509_free);
    }
    memset(identity, 0, sizeof(*identity));
}

uint8_t* identity_sign_blob(const SignerIdentity* identity, const uint8_t* data,
                            size_t size, size_t* outSize) {
    CMS_ContentInfo* cms =
        CMS_sign((X509*)identity->cert, (EVP_PKEY*)identity->key,
                 (STACK_OF(X509)*)identity->chain, NULL, CMS_PARTIAL | CMS_DETACHED | CMS_BINARY);
    if (cms == NULL) {
        return NULL;
    }

    BIO* bio = BIO_new_mem_buf(data, (int)size);
    if (bio == NULL) {
        CMS_ContentInfo_free(cms);
        return NULL;
    }
    if (CMS_final(cms, bio, NULL, CMS_DETACHED | CMS_BINARY) != 1) {
        BIO_free(bio);
        CMS_ContentInfo_free(cms);
        return NULL;
    }
    BIO_free(bio);

    unsigned char* der = NULL;
    int derSize = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (derSize <= 0 || der == NULL) {
        return NULL;
    }

    size_t total = 8 + (size_t)derSize;
    uint8_t* blob = malloc(total);
    if (blob == NULL) {
        OPENSSL_free(der);
        return NULL;
    }
    write32be(blob, CSMAGIC_BLOBWRAPPER);
    write32be(blob + 4, (uint32_t)total);
    memcpy(blob + 8, der, (size_t)derSize);
    OPENSSL_free(der);

    *outSize = total;
    return blob;
}
