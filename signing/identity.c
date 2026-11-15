#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "identity.h"

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

int identity_load_p12(SignerIdentity* identity, const uint8_t* data, size_t size,
                      const char* password, char* error, size_t errorSize) {
    memset(identity, 0, sizeof(*identity));

    const unsigned char* cursor = data;
    PKCS12* p12 = d2i_PKCS12(NULL, &cursor, (long)size);
    if (p12 == NULL) {
        set_error(error, errorSize, "invalid PKCS#12 data");
        return -1;
    }

    if (PKCS12_parse(p12, password, (EVP_PKEY**)&identity->key, (X509**)&identity->cert,
                     (STACK_OF(X509)**)&identity->chain) != 1) {
        set_error(error, errorSize, "failed to parse PKCS#12 (wrong password?)");
        PKCS12_free(p12);
        return -1;
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
