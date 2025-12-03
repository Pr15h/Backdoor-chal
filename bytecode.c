#include "bytecode.h"
#include <string.h>
#include <stdlib.h>

static void ensure(bc_t *b, size_t extra) {
    if (!b->buf) { b->cap = 1024; b->buf = malloc(b->cap); b->len = 0; }
    while (b->len + extra > b->cap) b->cap *= 2, b->buf = realloc(b->buf, b->cap);
}
void bc_init(bc_t *bc) { memset(bc,0,sizeof(*bc)); }
void bc_free(bc_t *bc) { if (bc->buf) free(bc->buf); memset(bc,0,sizeof(*bc)); }
size_t bc_pos(bc_t *bc) { return bc->len; }
vm_byte_t *bc_ptr(bc_t *bc) { return bc->buf; }
void bc_emit_u8(bc_t *bc, uint8_t v) { ensure(bc,1); bc->buf[bc->len++] = v; }
void bc_emit_s32(bc_t *bc, int32_t v) { ensure(bc,4); memcpy(bc->buf + bc->len, &v, 4); bc->len += 4; }
void bc_emit_u64(bc_t *bc, uint64_t v) { ensure(bc,8); memcpy(bc->buf + bc->len, &v, 8); bc->len += 8; }
void bc_emit_s64(bc_t *bc, int64_t v) { ensure(bc,8); memcpy(bc->buf + bc->len, &v, 8); bc->len += 8; }
