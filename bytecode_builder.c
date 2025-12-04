#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "vm.h"
#define REG_TMP0        0   
#define REG_TMP1        1  
#define REG_FAIL        2   
#define REG_HOLE_TEMP   3   
#define REG_INPUT_BASE  16 
#define REG_RAX         0  

#define COLS 25
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

static void emit_jz(Buf *out, uint32_t target_pc){
    put1(out, OP_JZ);
    put4(out, target_pc);
}

static void emit_jmp(Buf *out, uint32_t target_pc){
    put1(out, OP_JMP);
    put4(out, target_pc);
}

static void emit_halt(Buf *out){
    put1(out, OP_HALT);
}

uint8_t *build_game_bytecode(const int holes[COLS], size_t *out_len) {
    Buf out; buf_init(&out);

    for (int c = 0; c < COLS; ++c) {
        emit_mov_ri(&out, REG_HOLE_TEMP, (uint64_t)holes[c]);
        for (int r = 0; r < ROWS; ++r) {
            emit_mov_ri(&out, REG_TMP0, (uint64_t)r);
            emit_cmp_rr(&out, REG_TMP0, REG_HOLE_TEMP);
            uint32_t jz_pos = (uint32_t)out.len;
            emit_jz(&out, 0xDEADBEEF);
            emit_mov_ri(&out, REG_TMP1, 1);
            uint32_t jmp_pos = (uint32_t)out.len;
            emit_jmp(&out, 0xDEADBEEF);
            uint32_t label_set_zero_pc = (uint32_t)out.len;
            emit_mov_ri(&out, REG_TMP1, 0);
            uint32_t label_inner_next_pc = (uint32_t)out.len;
            memcpy(out.b + jz_pos + 1, &label_set_zero_pc, 4);
            memcpy(out.b + jmp_pos + 1, &label_inner_next_pc, 4);
        }
    }

    emit_mov_ri(&out, REG_FAIL, 0);

    for (int c = 0; c < COLS; ++c) {
        emit_mov_ri(&out, REG_HOLE_TEMP, (uint64_t)holes[c]);
        emit_mov_rr(&out, REG_TMP0, (uint8_t)(REG_INPUT_BASE + c));
        emit_cmp_rr(&out, REG_TMP0, REG_HOLE_TEMP);
        uint32_t jz_pos = (uint32_t)out.len;
        emit_jz(&out, 0xDEADBEEF);
        emit_mov_ri(&out, REG_FAIL, 1);
        uint32_t jmp_pos = (uint32_t)out.len;
        emit_jmp(&out, 0xDEADBEEF);
        uint32_t good_label_pc = (uint32_t)out.len;
        memcpy(out.b + jz_pos + 1, &good_label_pc, 4);
    }


    uint8_t *old = out.b;
    size_t grid_only_len = out.len;
    Buf out2; buf_init(&out2);

    for (int c = 0; c < COLS; ++c) {
        emit_mov_ri(&out2, REG_HOLE_TEMP, (uint64_t)holes[c]);
        for (int r = 0; r < ROWS; ++r) {
            emit_mov_ri(&out2, REG_TMP0, (uint64_t)r);
            emit_cmp_rr(&out2, REG_TMP0, REG_HOLE_TEMP);
            uint32_t jz_pos = (uint32_t)out2.len;
            emit_jz(&out2, 0xDEADBEEF);
            emit_mov_ri(&out2, REG_TMP1, 1);
            uint32_t jmp_pos = (uint32_t)out2.len;
            emit_jmp(&out2, 0xDEADBEEF);
            uint32_t label_set_zero_pc = (uint32_t)out2.len;
            emit_mov_ri(&out2, REG_TMP1, 0);
            uint32_t label_inner_next_pc = (uint32_t)out2.len;
            memcpy(out2.b + jz_pos + 1, &label_set_zero_pc, 4);
            memcpy(out2.b + jmp_pos + 1, &label_inner_next_pc, 4);
        }
    }

    emit_mov_ri(&out2, REG_FAIL, 0);
    for (int c = 0; c < COLS; ++c) {
        emit_mov_ri(&out2, REG_HOLE_TEMP, (uint64_t)holes[c]);
        emit_mov_rr(&out2, REG_TMP0, (uint8_t)(REG_INPUT_BASE + c));
        emit_cmp_rr(&out2, REG_TMP0, REG_HOLE_TEMP);
        uint32_t jz_pos = (uint32_t)out2.len;
        emit_jz(&out2, 0xDEADBEEF);
        emit_mov_ri(&out2, REG_FAIL, 1);
        uint32_t good_label_pc = (uint32_t)out2.len;
        memcpy(out2.b + jz_pos + 1, &good_label_pc, 4);
    }

    emit_mov_rr(&out2, REG_TMP0, REG_FAIL);
    emit_mov_ri(&out2, REG_HOLE_TEMP, 0);
    emit_cmp_rr(&out2, REG_TMP0, REG_HOLE_TEMP);
    uint32_t jz_pos_final = (uint32_t)out2.len;
    emit_jz(&out2, 0xDEADBEEF);
    emit_mov_ri(&out2, REG_RAX, 0);
    uint32_t jmp_to_halt = (uint32_t)out2.len;
    emit_jmp(&out2, 0xDEADBEEF); 
    uint32_t success_pc = (uint32_t)out2.len;
    emit_mov_ri(&out2, REG_RAX, 1);
    uint32_t halt_pc = (uint32_t)out2.len;
    emit_halt(&out2);

    memcpy(out2.b + jz_pos_final + 1, &success_pc, 4);

    memcpy(out2.b + jmp_to_halt + 1, &halt_pc, 4);

    if (old) free(old);

    *out_len = out2.len;
    return out2.b;
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
