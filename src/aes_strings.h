#ifndef AES_STRINGS_H
#define AES_STRINGS_H

#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static const uint8_t DEMO_KEY[32] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
};

static const uint8_t DEMO_IV[16] = {
    0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,
    0x11,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00
};

static inline char *aes_decrypt_string(const uint8_t *cipher, size_t len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    char *out = malloc(len + 32);
    int outlen1 = 0, outlen2 = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, DEMO_KEY, DEMO_IV);
    EVP_DecryptUpdate(ctx, (unsigned char*)out, &outlen1, cipher, (int)len);
    EVP_DecryptFinal_ex(ctx, (unsigned char*)out + outlen1, &outlen2);

    out[outlen1 + outlen2] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    return out;
}

#endif
