#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "magic_expand.h"
#include "vm.h"

#ifndef REG_INPUT_BASE
#define REG_INPUT_BASE 16
#endif

#ifndef REG_HOLE_BASE
#define REG_HOLE_BASE 41
#endif

static uint64_t g_magic_seed   = 0;
static int      g_magic_inited = 0;

static uint64_t get_random_seed_from_os(void) {
    uint64_t s = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, &s, sizeof(s));
        (void)r;
        close(fd);
        if (s != 0) return s;
    }
    s = (uint64_t)time(NULL);
    s ^= ((uint64_t)getpid() << 32);
    return s ? s : 0xDEADBEEFCAFEBABEULL;
}

void magic_init(uint64_t seed) {
    if (seed == 0) seed = get_random_seed_from_os();
    g_magic_seed = seed;
    srand((unsigned)(seed ^ (seed >> 32)));
    g_magic_inited = 1;
}

uint64_t magic_seed(void) {
    return g_magic_seed;
}

void magic_generate_holes(int *out, size_t n) {
    if (!out || n == 0) return;
    if (!g_magic_inited) magic_init(0);
    for (size_t i = 0; i < n; ++i) {
        out[i] = rand() % 6;
    }
}

void magic_generate_holes_for_vm(struct VM *vm_ptr) {
    if (!vm_ptr) return;

    int holes[25];
    memset(holes, 0, sizeof(holes));
    magic_generate_holes(holes, 25);

    for (int i = 0; i < 25; ++i) {
        vm_ptr->holes[i] = holes[i];
    }

    for (int i = 0; i < 25; ++i) {
        int base_val = holes[i];
        int transformed = (base_val * 7) + (i * 3) + 11;
        size_t ridx = (size_t)(REG_HOLE_BASE + i);
        if (ridx < VM_NUM_REGS) {
            vm_ptr->regs[ridx] = (vm_word_t)transformed;
        }
    }
}

void magic_expand_and_execute(void *v) {
    (void)v;
}

static int apply_transform(int idx, int base_val) {
    switch (idx % 40) {
        case 0:  return (base_val * 5) ^ 2;
        case 1:  return base_val + 6 * 7;
        case 2:  return (base_val << 3) + 13;
        case 3:  return (base_val * base_val) + 17;
        case 4:  return (base_val ^ 0xA) + 3;
        case 5:  return base_val * 11 - 4;
        case 6:  return (base_val * 7) ^ 0x5;
        case 7:  return base_val + (idx * 3) + 19;
        case 8:  return (base_val * 4) + (idx ^ 0x3);
        case 9:  return (base_val << 2) ^ (idx + 1);
        case 10: return base_val * 3 + 31;
        case 11: return (base_val + 2) * (idx + 1);
        case 12: return (base_val * 13) - (idx % 5);
        case 13: return (base_val ^ (idx * 7)) + 2;
        case 14: return (base_val + 1) * (base_val + idx);
        case 15: return (base_val * 6) ^ ((idx << 1) | 3);
        case 16: return base_val * (idx + 2) + 17;
        case 17: return (base_val + 4) * 5 - (idx % 3);
        case 18: return (base_val ^ 0xF) + (idx * 2);
        case 19: return (base_val * 2) + (idx * idx);
        case 20: return (base_val << 1) ^ (idx + 9);
        case 21: return (base_val * 9) - (idx % 7);
        case 22: return (base_val + idx) * 3;
        case 23: return (base_val * 17) ^ (idx + 5);
        case 24: return (base_val * base_val) + (idx * 2) + 1;
        case 25: return (base_val * 5) + idx;
        case 26: return (base_val ^ 0x7) - (idx % 11);
        case 27: return (base_val * 2) + (idx * 3);
        case 28: return (base_val << 4) ^ idx;
        case 29: return (base_val + 8) * (idx + 2);
        case 30: return (base_val * 12) - (idx % 9);
        case 31: return (base_val ^ (idx * 3)) + 7;
        case 32: return (base_val + idx) * (base_val + 1);
        case 33: return (base_val * 3) ^ (idx + 13);
        case 34: return (base_val << 2) + (idx % 5);
        case 35: return (base_val * 4) - (idx / 2);
        case 36: return (base_val ^ 0xC) + (idx * idx);
        case 37: return (base_val * 7) + (idx % 4);
        case 38: return (base_val + 3) * (idx + 1);
        case 39: return (base_val * base_val) ^ (idx + 19);
        default: return base_val;
    }
}