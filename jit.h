#ifndef JIT_H
#define JIT_H

#include <stdint.h>
#include <stddef.h>
#include "vm.h"


typedef struct {
    void *code;      
    size_t size;    
    int (*fn)(VM *vm); 
} JITUnit;

JITUnit *jit_compile(VM *vm, const vm_byte_t *code, size_t code_size);

void jit_free(JITUnit *u);

#endif
