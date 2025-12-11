#ifndef JIT_H
#define JIT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "vm.h"

typedef struct JITUnit {
    void *code;
    size_t size;
    int  (*fn)(VM *vm);
} JITUnit;

JITUnit *jit_compile(VM *vm, const vm_byte_t *code, size_t code_size);

void jit_free(JITUnit *u);

#define JIT_ERR_STALE_MAP 1

#ifdef HAS_JIT_RUN_UNIT
int jit_run_unit(JITUnit *unit, VM *vm);
#endif

#ifdef __cplusplus
}
#endif

#endif
