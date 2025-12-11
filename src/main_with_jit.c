#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#include "vm.h"
#include "jit.h"
#include "aes_strings.h"
#include "magic_expand.h"

#ifndef REG_INPUT_BASE
#define REG_INPUT_BASE 16
#endif
#ifndef REG_RAX
#define REG_RAX 0
#endif

#define OP_MAGIC 0xF0
#define OP_MAGIC_SITE_HOLES 0x42

static const uint8_t ENC_STR_WELCOME[] = {0x91, 0x9e, 0x9c, 0x65, 0xb7, 0xb3, 0xb7, 0x6b, 0x5e, 0x1f, 0x14, 0x96,
0x31, 0xa6, 0xf7, 0xb1, 0x6e, 0xa8, 0x0a, 0x24, 0x19, 0x71, 0x90, 0xe1,
0xd0, 0xc1, 0xee, 0xd8, 0x66, 0x48, 0x37, 0xf0, 0x48, 0xb4, 0x48, 0x19,
0xfe, 0x90, 0x9c, 0xba, 0x1f, 0x1c, 0x9f, 0x8e, 0x15, 0x45, 0x09, 0x0a,
0xb7, 0x21, 0x43, 0xa4, 0x5b, 0x45, 0xbe, 0x76, 0xba, 0x9f, 0xcb, 0x53,
0x1a, 0x5d, 0xc6, 0xaf};

static const uint8_t ENC_INFO[]={0x56, 0x3f, 0x8b, 0x5c, 0x76, 0x1f, 0x3f, 0xa6, 0xab, 0x20, 0x81, 0x7a,
0x1b, 0xb8, 0x62, 0xfb, 0x45, 0xb4, 0x72, 0xca, 0x2c, 0x28, 0x18, 0x6e,
0x0d, 0x04, 0x1b, 0xfd, 0x35, 0x8f, 0x06, 0xc8, 0x2a, 0x07, 0xb4, 0xbf,
0x58, 0x04, 0x2e, 0x53, 0xe5, 0x40, 0x6b, 0x9c, 0x57, 0x2e, 0xcc, 0x1b,
0xf5, 0x65, 0x66, 0x8d, 0x10, 0xd1, 0xec, 0x12, 0x1c, 0x26, 0x03, 0xaf,
0x64, 0x56, 0x20, 0xf5};

static const size_t ENC_STR_WELCOME_LEN = sizeof(ENC_STR_WELCOME);
static const size_t ENC_INFO_LEN=sizeof(ENC_INFO);

uint8_t *build_game_bytecode(const int holes[], size_t *out_len);

static ssize_t find_magic_holes_site(const uint8_t *code, size_t len) {
    if (!code) return -1;
    for (size_t i = 0; i + 1 < len; ++i) {
        if (code[i] == OP_MAGIC && code[i+1] == OP_MAGIC_SITE_HOLES) return (ssize_t)i;
    }
    return -1;
}

int main(void) {
    char *s1 = aes_decrypt_string(ENC_STR_WELCOME, ENC_STR_WELCOME_LEN);
    char *s2 = aes_decrypt_string(ENC_INFO, ENC_INFO_LEN);
    if (s1) { puts(s1); free(s1); }
    if (s2) { puts(s2); free(s2); }

    unsigned seed = (unsigned)time(NULL);
    srand(seed);

    magic_init(0);

    VM vm_instance;
    memset(&vm_instance, 0, sizeof(vm_instance));
    VM *vm = &vm_instance;

    size_t nregs = VM_NUM_REGS;
    if (nregs < (size_t)(REG_INPUT_BASE + 40)) {
        return 1;
    }

    #ifndef REG_HOLE_BASE
    #define REG_HOLE_BASE 41
    #endif
    if (nregs < (size_t)(REG_HOLE_BASE + 40)) {
        return 1;
    }

    if ((size_t)REG_RAX >= nregs) {
        return 1;
    }

    vm->callsp = -1;
    vm->pc = 0;
    vm->debug = 1;

    size_t bc_len = 0;
    uint8_t *bc = build_game_bytecode(NULL, &bc_len);
    if (!bc) {  return 1; }

    vm->code = bc;
    vm->code_size = bc_len;

    JITUnit *u = jit_compile(vm, bc, bc_len);

    ssize_t magic_pos = find_magic_holes_site(bc, bc_len);
    if (magic_pos >= 0) {
        ssize_t saved_pc = vm->pc;
        vm->pc = magic_pos;
        int step_ret = vm_step(vm);
        vm->pc = saved_pc;
    }

    if (!u) {
        free(bc);
        return 1;
    }

#ifdef HAS_JIT_RUN_UNIT
    int r = jit_run_unit(u, vm);
    if (r == JIT_ERR_STALE_MAP) {
        jit_free(u);
        u = jit_compile(vm, bc, bc_len);
        if (!u) {
            free(bc);
            return 1;
        } else {
            u->fn(vm);
        }
    }
#else
    int ret = u->fn(vm);
    (void)ret;
#endif
    jit_free(u);

    free(bc);
    return 0;
}
