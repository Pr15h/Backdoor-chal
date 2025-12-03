#ifndef BYTECODE_H
#define BYTECODE_H
#include <stdint.h>
#include <stdlib.h>
#include "vm.h"

typedef struct {
    vm_byte_t *buf;
    size_t len;
    size_t cap;
} bc_t;

void bc_init(bc_t *bc);
void bc_free(bc_t *bc);
size_t bc_pos(bc_t *bc);
vm_byte_t *bc_ptr(bc_t *bc);
void bc_emit_u8(bc_t *bc, uint8_t v);
void bc_emit_s32(bc_t *bc, int32_t v);
void bc_emit_u64(bc_t *bc, uint64_t v);
void bc_emit_s64(bc_t *bc, int64_t v);
#endif
