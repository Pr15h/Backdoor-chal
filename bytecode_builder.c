#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/sha.h>
#include "vm.h"

#define REG_TMP0        0
#define REG_TMP1        1
#define REG_FAIL        2
#define REG_HOLE_TEMP   3
#define REG_INPUT_BASE  16
#define REG_RAX         0

#ifndef REG_HOLE_BASE
#define REG_HOLE_BASE 41
#endif

#define COLS 40
#define ROWS 6

typedef struct { uint8_t *b; size_t len, cap; } Buf;
static void buf_init(Buf *b){ b->b=NULL; b->len=b->cap=0; }
static void buf_ensure(Buf *b, size_t n){ if(!b->b){ b->cap=4096; b->b=malloc(b->cap);} while(b->len+n> b->cap){ b->cap*=2; b->b=realloc(b->b,b->cap);} }
static void put1(Buf *b, uint8_t v){ buf_ensure(b,1); b->b[b->len++]=v; }
static void put4(Buf *b, uint32_t v){ buf_ensure(b,4); memcpy(b->b+b->len, &v, 4); b->len+=4; }
static void put8(Buf *b, uint64_t v){ buf_ensure(b,8); memcpy(b->b+b->len, &v, 8); b->len+=8; }

static void emit_mov_ri(Buf *out, uint8_t rd, uint64_t imm){
    put1(out, OP_MOV_RI);
    put1(out, rd);
    put8(out, imm);
}

static void emit_mov_rr(Buf *out, uint8_t rd, uint8_t rs){
    put1(out, OP_MOV_RR);
    put1(out, rd);
    put1(out, rs);
}

static void emit_cmp_rr(Buf *out, uint8_t ra, uint8_t rb){
    put1(out, OP_CMP_RR);
    put1(out, ra);
    put1(out, rb);
}

static void emit_jz(Buf *out, uint64_t target_pc){
    put1(out, OP_JZ);
    put8(out, target_pc);
}

static void emit_jmp(Buf *out, uint64_t target_pc){
    put1(out, OP_JMP);
    put8(out, target_pc);
}

static void emit_halt(Buf *out){
    put1(out, OP_HALT);
}

uint8_t *build_game_bytecode(const int holes_unused[COLS], size_t *out_len) {
    (void)holes_unused;
    Buf out; buf_init(&out);

    put1(&out, OP_MAGIC);
    put1(&out, OP_MAGIC_SITE_HOLES);

    for (int c = 0; c < COLS; ++c) {
        emit_mov_rr(&out, REG_HOLE_TEMP, (uint8_t)(REG_HOLE_BASE + c));
        for (int r = 0; r < ROWS; ++r) {
            emit_mov_ri(&out, REG_TMP0, (uint64_t)r);
            emit_cmp_rr(&out, REG_TMP0, REG_HOLE_TEMP);

            uint64_t jz_pos = (uint64_t)out.len;
            emit_jz(&out, 0ULL); 

            emit_mov_ri(&out, REG_TMP1, 1);

            uint64_t jmp_pos = (uint64_t)out.len;
            emit_jmp(&out, 0ULL); 

            uint64_t label_set_zero_pc = (uint64_t)out.len;
            emit_mov_ri(&out, REG_TMP1, 0);

            uint64_t label_inner_next_pc = (uint64_t)out.len;

            memcpy(out.b + (size_t)jz_pos + 1, &label_set_zero_pc, 8);
            memcpy(out.b + (size_t)jmp_pos + 1, &label_inner_next_pc, 8);
        }
    }

    emit_mov_ri(&out, REG_FAIL, 0);

    for (int c = 0; c < COLS; ++c) {
        emit_mov_rr(&out, REG_HOLE_TEMP, (uint8_t)(REG_HOLE_BASE + c));
        emit_mov_rr(&out, REG_TMP0, (uint8_t)(REG_INPUT_BASE + c));
        emit_cmp_rr(&out, REG_TMP0, REG_HOLE_TEMP);
        uint64_t jz_pos = (uint64_t)out.len;
        emit_jz(&out, 0ULL); 
        emit_mov_ri(&out, REG_FAIL, 1);
        uint64_t good_label_pc = (uint64_t)out.len;
        memcpy(out.b + (size_t)jz_pos + 1, &good_label_pc, 8);
    }

    emit_mov_rr(&out, REG_TMP0, REG_FAIL);
    emit_mov_ri(&out, REG_HOLE_TEMP, 0);
    emit_cmp_rr(&out, REG_TMP0, REG_HOLE_TEMP);
    uint64_t jz_pos_final = (uint64_t)out.len;
    emit_jz(&out, 0ULL); 
    emit_mov_ri(&out, REG_RAX, 0);
    uint64_t jmp_to_halt = (uint64_t)out.len;
    emit_jmp(&out, 0ULL); 
    uint64_t success_pc = (uint64_t)out.len;
    emit_mov_ri(&out, REG_RAX, 1);
    uint64_t halt_pc = (uint64_t)out.len;
    emit_halt(&out);

    memcpy(out.b + (size_t)jz_pos_final + 1, &success_pc, 8);
    memcpy(out.b + (size_t)jmp_to_halt + 1, &halt_pc, 8);

    uint8_t *plain = out.b;
    size_t plain_len = out.len;

    if (!plain || plain_len == 0) {
        if (out_len) *out_len = 0;
        return NULL;
    }

    uint64_t s = magic_seed();
    unsigned char seed_bytes[8];
    for (int i = 0; i < 8; ++i) seed_bytes[i] = (unsigned char)((s >> (8*i)) & 0xFF);
    unsigned char key[32];
    SHA256(seed_bytes, sizeof(seed_bytes), key);

    uint8_t *ct = malloc(plain_len);
    if (!ct) { free(plain); if (out_len) *out_len = 0; return NULL; }
    for (size_t i = 0; i < plain_len; ++i) ct[i] = plain[i] ^ key[i % sizeof(key)];

    size_t total = 4 + 8 + plain_len;
    uint8_t *blob = malloc(total);
    if (!blob) { free(plain); free(ct); if (out_len) *out_len = 0; return NULL; }
    memcpy(blob + 0, "ENCR", 4);
    uint64_t le_len = (uint64_t)plain_len;
    memcpy(blob + 4, &le_len, sizeof(le_len));
    memcpy(blob + 12, ct, plain_len);

    free(plain);
    free(ct);

    if (out_len) *out_len = total;
    return blob;
}

void example_usage(VM *vm) {
    int holes[COLS];
    for (int i = 0; i < COLS; ++i) holes[i] = rand() % ROWS;

    int inputs[COLS];
    for (int i = 0; i < COLS; ++i) {
        if (scanf("%d", &inputs[i]) != 1) { fprintf(stderr,"input error\n"); return; }
        if (inputs[i] < 0 || inputs[i] >= ROWS) { fprintf(stderr,"range\n"); return; }
    }
    for (int i = 0; i < COLS; ++i) {
        vm->regs[REG_INPUT_BASE + i] = (vm_word_t)inputs[i];
    }

    size_t bc_len;
    uint8_t *bc = build_game_bytecode(holes, &bc_len);
    if (!bc) { fprintf(stderr,"build failed\n"); return; }
    free(bc);
}
