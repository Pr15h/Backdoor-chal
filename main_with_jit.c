#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "vm.h"
#include "jit.h"
#include "aes_strings.h"
#ifndef REG_INPUT_BASE
#define REG_INPUT_BASE 16
#endif
#ifndef REG_RAX
#define REG_RAX 0
#endif

uint8_t *build_game_bytecode(const int holes[], size_t *out_len);

static const uint8_t ENC_STR_WELCOME[] = {0x91, 0x9e, 0x9c, 0x65, 0xb7, 0xb3, 0xb7, 0x6b, 0x5e, 0x1f, 0x14, 0x96,
0x31, 0xa6, 0xf7, 0xb1, 0x74, 0xa6, 0x28, 0xfb, 0xa9, 0x1f, 0x30, 0x77,
0x9f, 0xf3, 0x08, 0x46, 0x50, 0x33, 0xc6, 0x27, 0x22, 0x86, 0xf8, 0x90,
0x6c, 0xb8, 0x56, 0xff, 0x59, 0x7f, 0x2b, 0x86, 0xd5, 0x8b, 0xb0, 0x78,
0x23, 0x28, 0x6c, 0x08, 0xc7, 0xbc, 0x2d, 0x41, 0x17, 0x2b, 0x4d, 0xe6,
0xf3, 0x53, 0x8c, 0x9a, 0x1b, 0xb3, 0x02, 0x66, 0x6c, 0x0d, 0x63, 0x9e,
0xaf, 0xaf, 0x86, 0xf3, 0x15, 0x1c, 0x6d, 0xfc, 0x55, 0xc0, 0x93, 0xa5,
0x68, 0x13, 0xb1, 0x2d, 0xe8, 0xc1, 0x27, 0x0f, 0x77, 0xa9, 0xf5, 0xb3,
0x70, 0xb8, 0x55, 0x68, 0x07, 0x4b, 0x1b, 0x7a, 0x0b, 0x32, 0xe9, 0xdf,
0xcf, 0x15, 0x82, 0x43, 0x7a, 0xdf, 0xac, 0x46, 0x20, 0x2f, 0xac, 0xce,
0xad, 0xa7, 0x8b, 0x82, 0xb1, 0x39, 0x98, 0x75};

static const uint8_t ENC_INFO[]={0x3e, 0x1a, 0x15, 0x70, 0x6f, 0x52, 0x28, 0x4d, 0x52, 0xb6, 0xb1, 0xc3,
0xd8, 0xed, 0xde, 0x72, 0xb8, 0x3a, 0xc9, 0x79, 0xef, 0x49, 0x67, 0xcf,
0x93, 0x4c, 0xdc, 0xd9, 0x76, 0xdc, 0x48, 0xf9, 0xec, 0x4e, 0x38, 0x79,
0x3a, 0xa0, 0x72, 0xa4, 0x70, 0xda, 0xe3, 0x42, 0xcb, 0xb6, 0x5e, 0x73};

static const size_t ENC_STR_WELCOME_LEN = sizeof(ENC_STR_WELCOME);
static const size_t ENC_INFO_LEN=sizeof(ENC_INFO);
int main(void) {
    char *s1 = aes_decrypt_string(ENC_STR_WELCOME, ENC_STR_WELCOME_LEN);
    char *s2=aes_decrypt_string(ENC_INFO,ENC_INFO_LEN);
    puts(s1);
    free(s1);
    puts(s2);
    free(s2);

    unsigned seed = (unsigned)time(NULL);
    srand(seed);
    // fprintf(stderr, "debug: srand seed = %u\n", seed);

    int holes[25];
    for (int i = 0; i < 25; ++i) holes[i] = rand() % 6;

    // fprintf(stderr, "debug holes: ");
    // for (int i = 0; i < 25; ++i) fprintf(stderr, "%d ", holes[i]);
    // fprintf(stderr, "\n");

    int inputs[25];
    for (int i = 0; i < 25; ++i) {
        if (scanf("%d", &inputs[i]) != 1) { fprintf(stderr, "input should be integer\n"); return 1; }
        if (inputs[i] < 0 || inputs[i] >= 6)  { fprintf(stderr, "input out of range\n"); return 1; }
    }

    VM vm_instance;
    memset(&vm_instance, 0, sizeof(vm_instance));
    VM *vm = &vm_instance;

    size_t nregs = VM_NUM_REGS;
    if (nregs < (size_t)(REG_INPUT_BASE + 25)) {
        fprintf(stderr, "ERROR: VM_NUM_REGS=%zu too small for REG_INPUT_BASE+25=%d\n", nregs, REG_INPUT_BASE + 25);
        return 1;
    }
    if ((size_t)REG_RAX >= nregs) {
        fprintf(stderr, "ERROR: REG_RAX=%d out of range (0..%zu)\n", REG_RAX, nregs-1);
        return 1;
    }
    for (int i = 0; i < 25; ++i) {
        vm->regs[REG_INPUT_BASE + i] = (vm_word_t)inputs[i];
    }

    size_t bc_len = 0;
    uint8_t *bc = build_game_bytecode(holes, &bc_len);
    if (!bc) { fprintf(stderr, "failed to build bytecode\n"); return 1; }
    // fprintf(stderr, "built bytecode len=%zu\n", bc_len);
    JITUnit *u = jit_compile(vm, bc, bc_len);
    if (!u) { fprintf(stderr, "jit_compile failed\n"); free(bc); return 1; }
    // fprintf(stderr, "jit compiled -> code=%p size=%zu\n", u->code, u->size);

    int ret = u->fn(vm);
    // fprintf(stderr, "jit fn returned %d, regs[RAX]=%llu\n", ret, (unsigned long long)vm->regs[REG_RAX]);

    if (vm->regs[REG_RAX] != 0) {
        puts("Success! Decrypt and show the flag now.");
    } else {
        puts("Failure: checks didn't pass.");
    }

    jit_free(u);
    free(bc);

    return 0;
}
