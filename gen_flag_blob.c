#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#define NUM_AES_PARTS 8
#define REG_INPUT_BASE 16
#define VM_NUM_REGS 128

typedef int64_t vm_word_t;

typedef struct {
    vm_word_t regs[VM_NUM_REGS];
} VM;

static int32_t transform_input(int idx, int32_t v) {
    switch (idx % 5) {
        case 0: return (v * 5) ^ 2;
        case 1: return v + 6 * 7;
        case 2: return (v ^ 0x3a) - 11;
        case 3: return v * v + 13;
        case 4: return (v - 3) * 9;
        default: return v;
    }
}

static void derive_key_from_inputs(VM *vm, unsigned char out_key[32]) {
    unsigned char buf[NUM_AES_PARTS * 4];

    for (int i = 0; i < NUM_AES_PARTS; ++i) {
        int32_t v = 0;
        size_t ridx = (size_t)(REG_INPUT_BASE + i);
        if (ridx < VM_NUM_REGS) {
            v = (int32_t)vm->regs[ridx];
        }

        int32_t t = transform_input(i, v);

        buf[i*4 + 0] = (unsigned char)((uint32_t)t & 0xFF);
        buf[i*4 + 1] = (unsigned char)(((uint32_t)t >> 8) & 0xFF);
        buf[i*4 + 2] = (unsigned char)(((uint32_t)t >> 16) & 0xFF);
        buf[i*4 + 3] = (unsigned char)(((uint32_t)t >> 24) & 0xFF);
    }

    SHA256(buf, sizeof(buf), out_key);

    volatile unsigned char *p = buf;
    for (size_t i = 0; i < sizeof(buf); ++i) p[i] = 0;
}

static void print_c_array(const char *name, const unsigned char *data, size_t len) {
    printf("static const unsigned char %s[] = {", name);
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) printf("\n    ");
        printf("0x%02x", data[i]);
        if (i + 1 != len) printf(", ");
    }
    printf("\n};\nstatic const size_t %s_LEN = %zu;\n\n", name, len);
}

static void print_int_array(const char *name, const int *data, size_t len) {
    printf("static const int %s[] = {", name);
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) printf("\n    ");
        printf("%d", data[i]);
        if (i + 1 != len) printf(", ");
    }
    printf("\n};\nstatic const size_t %s_LEN = %zu;\n\n", name, len);
}

int main(void) {
    VM vm;
    memset(&vm, 0, sizeof(vm));

    int correct_inputs[40] = {
        0, 3, 5, 2, 1, 4, 1, 2,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    };

    for (int i = 0; i < 40; ++i) {
        size_t ridx = (size_t)(REG_INPUT_BASE + i);
        vm.regs[ridx] = (vm_word_t)correct_inputs[i];
    }

    unsigned char key[32];
    derive_key_from_inputs(&vm, key);

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return 1;
    }

    const unsigned char flag[] = "1_4m_4_h1gh_p3rm0rm4nc3_4thl3te_sw3a7_b4by";
    int flag_len = (int)strlen((const char*)flag);

    int block = 16;
    int pad_len = block - (flag_len % block);
    int padded_len = flag_len + pad_len;
    unsigned char *padded = malloc((size_t)padded_len);
    if (!padded) return 1;
    memcpy(padded, flag, (size_t)flag_len);
    memset(padded + flag_len, pad_len, (size_t)pad_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        free(padded);
        return 1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "EncryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(padded);
        return 1;
    }

    unsigned char ct[512];
    int len = 0, ct_len = 0;

    if (!EVP_EncryptUpdate(ctx, ct, &len, padded, padded_len)) {
        fprintf(stderr, "EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(padded);
        return 1;
    }
    ct_len += len;

    if (!EVP_EncryptFinal_ex(ctx, ct + ct_len, &len)) {
        fprintf(stderr, "EncryptFinal failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(padded);
        return 1;
    }
    ct_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(padded);

    print_int_array("correct_inputs", correct_inputs, 40);
    print_c_array("FLAG_CT", ct, (size_t)ct_len);
    print_c_array("FLAG_IV", iv, sizeof(iv));

    volatile unsigned char *kp = key;
    for (size_t i = 0; i < sizeof(key); ++i) kp[i] = 0;

    return 0;
}