#ifndef MAGIC_EXPAND_H
#define MAGIC_EXPAND_H

#include <stddef.h>
#include <stdint.h>

struct VM;

#ifdef __cplusplus
extern "C" {
#endif

void magic_init(uint64_t seed);
void magic_generate_holes(int *out, size_t n);


void magic_generate_holes_for_vm(struct VM *vm);

void magic_expand_and_execute(void *vm);

uint64_t magic_seed(void);

#ifdef __cplusplus
}
#endif

#endif
