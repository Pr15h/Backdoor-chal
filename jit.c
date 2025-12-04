#define _GNU_SOURCE
#include "jit.h"
#include "vm.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
#endif

#ifndef JIT_RETURN_REG
#define JIT_RETURN_REG RAX
#endif

struct JITUnit { void *code; size_t size; int (*fn)(VM*); };
void jit_free(JITUnit *u) {
    if (!u) return;
    if (u->code) {
#ifdef _WIN32
        VirtualFree(u->code, 0, MEM_RELEASE);
#else
        size_t pagesz = (size_t)sysconf(_SC_PAGESIZE);
        size_t round = (u->size + pagesz - 1) & ~(pagesz - 1);
        munmap(u->code, round);
#endif
    }
    free(u);
}

static void jit_helper_write_reg(VM *vm, uint32_t rd, uint64_t imm) {
    if (!vm) return;
    if (rd < VM_NUM_REGS) vm->regs[rd] = (vm_word_t)imm;
}

typedef struct { uint8_t *b; size_t len, cap; } CB;
static void cb_init(CB *c){ c->b=NULL; c->len=c->cap=0; }
static void cb_grow(CB *c, size_t n){
    if(!c->b){
        c->cap=4096;
        c->b=malloc(c->cap);
        c->len=0;
    }
    while(c->len+n>c->cap){
        c->cap*=2;
        c->b=realloc(c->b,c->cap);
    }
}
static void cb_put1(CB *c, uint8_t v){ cb_grow(c,1); c->b[c->len++]=v; }
static void cb_put4(CB *c, uint32_t v){ cb_grow(c,4); memcpy(c->b+c->len,&v,4); c->len+=4; }
static void cb_put8(CB *c, uint64_t v){ cb_grow(c,8); memcpy(c->b+c->len,&v,8); c->len+=8; }

static void *alloc_exec(size_t s){
#ifdef _WIN32
    return VirtualAlloc(NULL,s,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
#else
    size_t pagesz=(size_t)sysconf(_SC_PAGESIZE);
    s=(s+pagesz-1)&~(pagesz-1);
    void *p=mmap(NULL,s,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED) return NULL;
    return p;
#endif
}
static int make_exec(void *p,size_t s){
#ifdef _WIN32
    DWORD old; return VirtualProtect(p,s,PAGE_EXECUTE_READ,&old)?0:-1;
#else
    size_t pagesz=(size_t)sysconf(_SC_PAGESIZE);
    s=(s+pagesz-1)&~(pagesz-1);
    return mprotect(p,s,PROT_READ|PROT_EXEC);
#endif
}

static void emit_call_write_reg(CB *cb, void *helper, uint32_t rd, uint64_t imm) {
#ifdef _WIN32
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x4D); cb_put1(cb, 0xF8);
    cb_put1(cb, 0xBA); cb_put4(cb, (uint32_t)rd);
    cb_put1(cb, 0x49); cb_put1(cb, 0xB8); cb_put8(cb, imm);
    cb_put1(cb, 0x48); cb_put1(cb, 0xB8); cb_put8(cb, (uint64_t)(uintptr_t)helper);
    cb_put1(cb, 0xFF); cb_put1(cb, 0xD0);
#else
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x7D); cb_put1(cb, 0xF8);
    cb_put1(cb, 0xBE); cb_put4(cb, (uint32_t)rd);
    cb_put1(cb, 0x48); cb_put1(cb, 0xBA); cb_put8(cb, imm);
    cb_put1(cb, 0x48); cb_put1(cb, 0xB8); cb_put8(cb, (uint64_t)(uintptr_t)helper);
    cb_put1(cb, 0xFF); cb_put1(cb, 0xD0);
#endif
}


static void emit_mov_rr_native(CB *cb, uint8_t rd, uint8_t rs) {
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x45); cb_put1(cb, 0xF8);
    uint32_t off_rs = (uint32_t)(offsetof(VM, regs) + (size_t)rs * sizeof(vm_word_t));
    cb_put1(cb, 0x48); cb_put1(cb, 0x05); cb_put4(cb, off_rs);
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x10);
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x45); cb_put1(cb, 0xF8);
    uint32_t off_rd = (uint32_t)(offsetof(VM, regs) + (size_t)rd * sizeof(vm_word_t));
    cb_put1(cb, 0x48); cb_put1(cb, 0x05); cb_put4(cb, off_rd);
    cb_put1(cb, 0x48); cb_put1(cb, 0x89); cb_put1(cb, 0x10);
}

static void emit_cmp_rr_native(CB *cb, uint8_t ra, uint8_t rb) {

    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x45); cb_put1(cb, 0xF8);
    uint32_t off_ra = (uint32_t)(offsetof(VM, regs) + (size_t)ra * sizeof(vm_word_t));
    cb_put1(cb, 0x48); cb_put1(cb, 0x05); cb_put4(cb, off_ra);

    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x00);

    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x55); cb_put1(cb, 0xF8); 
    uint32_t off_rb = (uint32_t)(offsetof(VM, regs) + (size_t)rb * sizeof(vm_word_t));
    cb_put1(cb, 0x48); cb_put1(cb, 0x81); cb_put1(cb, 0xC2); cb_put4(cb, off_rb); 
    
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x12);

    cb_put1(cb, 0x48); cb_put1(cb, 0x39); cb_put1(cb, 0xD0);
}


static void emit_epilogue_return_regs_rax(CB *cb) {
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x45); cb_put1(cb, 0xF8);
    uint32_t off_regs = (uint32_t)offsetof(VM, regs);
    uint32_t off_ret = off_regs + (uint32_t)((size_t)JIT_RETURN_REG * sizeof(vm_word_t));
    cb_put1(cb, 0x48); cb_put1(cb, 0x05); cb_put4(cb, off_ret);
    cb_put1(cb, 0x48); cb_put1(cb, 0x8B); cb_put1(cb, 0x00);
    cb_put1(cb, 0xC9); cb_put1(cb, 0xC3);
}

typedef enum { PATCH_JZ, PATCH_JMP } PatchType;
typedef struct {
    size_t instr_offset;
    size_t target_pc;
    PatchType type;
} PatchEntry;

JITUnit *jit_compile(VM *vm, const vm_byte_t *code, size_t code_size) {
    (void)vm;
    if (!code || code_size == 0) return NULL;
    CB cb; cb_init(&cb);

    size_t *pc_to_out = malloc(sizeof(size_t) * code_size);
    if (!pc_to_out) return NULL;
    for (size_t i = 0; i < code_size; ++i) pc_to_out[i] = (size_t)-1;

    PatchEntry *patches = NULL;
    size_t patches_len = 0, patches_cap = 0;
    #define PATCH_PUSH(pe) do { \
        if (patches_len+1 > patches_cap) { \
            patches_cap = patches_cap ? patches_cap*2 : 64; \
            patches = realloc(patches, patches_cap * sizeof(PatchEntry)); \
        } \
        patches[patches_len++] = (pe); \
    } while(0)

    /* prologue */
    cb_put1(&cb, 0x55);
    cb_put1(&cb, 0x48); cb_put1(&cb, 0x89); cb_put1(&cb, 0xE5);
    cb_put1(&cb, 0x48); cb_put1(&cb, 0x83); cb_put1(&cb, 0xEC); cb_put1(&cb, 0x20);
#ifdef _WIN32
    cb_put1(&cb, 0x48); cb_put1(&cb, 0x89); cb_put1(&cb, 0x4D); cb_put1(&cb, 0xF8);
#else
    cb_put1(&cb, 0x48); cb_put1(&cb, 0x89); cb_put1(&cb, 0x7D); cb_put1(&cb, 0xF8);
#endif

    size_t pc = 0;
    while (pc < code_size) {
        pc_to_out[pc] = cb.len;
        uint8_t op = code[pc];

        if (op == OP_MOV_RI) {
            if (pc + 10 > code_size) goto fail;
            uint8_t rd = code[pc+1];
            if (rd >= VM_NUM_REGS) goto fail;
            uint64_t imm; memcpy(&imm, code + pc + 2, 8);
            emit_call_write_reg(&cb, (void*)jit_helper_write_reg, (uint32_t)rd, imm);
            pc += 10;
            continue;
        }

        if (op == OP_MOV_RR) {
            if (pc + 3 > code_size) goto fail;
            uint8_t rd = code[pc+1];
            uint8_t rs = code[pc+2];
            if (rd >= VM_NUM_REGS || rs >= VM_NUM_REGS) goto fail;
            emit_mov_rr_native(&cb, rd, rs);
            pc += 3;
            continue;
        }

        if (op == OP_CMP_RR) {
            if (pc + 3 > code_size) goto fail;
            uint8_t ra = code[pc+1];
            uint8_t rb = code[pc+2];
            if (ra >= VM_NUM_REGS || rb >= VM_NUM_REGS) goto fail;
            emit_cmp_rr_native(&cb, ra, rb);
            pc += 3;
            continue;
        }

        if (op == OP_JZ) {
            if (pc + 5 > code_size) goto fail;
            uint32_t target; memcpy(&target, code + pc + 1, 4);
            size_t instr_off = cb.len;
            cb_put1(&cb, 0x0F); cb_put1(&cb, 0x84); cb_put4(&cb, 0x0);
            PatchEntry pe = { instr_off, (size_t)target, PATCH_JZ };
            PATCH_PUSH(pe);
            pc += 5;
            continue;
        }

        if (op == OP_JMP) {
            if (pc + 5 > code_size) goto fail;
            uint32_t target; memcpy(&target, code + pc + 1, 4);
            size_t instr_off = cb.len;
            cb_put1(&cb, 0xE9); cb_put4(&cb, 0x0);
            PatchEntry pe = { instr_off, (size_t)target, PATCH_JMP };
            PATCH_PUSH(pe);
            pc += 5;
            continue;
        }

        if (op == OP_HALT) {
            emit_epilogue_return_regs_rax(&cb);
            pc += 1;
            break;
        }

        if (op == OP_DB) {
            if (pc + 2 > code_size) goto fail;
            cb_put1(&cb, code[pc+1]);
            pc += 2;
            continue;
        }

        goto fail;
    }

    for (size_t i = 0; i < patches_len; ++i) {
        PatchEntry *p = &patches[i];
        if (p->target_pc >= code_size) goto fail;
        size_t dest_off = pc_to_out[p->target_pc];
        if (dest_off == (size_t)-1) goto fail;

        if (p->type == PATCH_JZ) {
            size_t instr_off = p->instr_offset;
            size_t next_instr = instr_off + 6;
            int32_t rel = (int32_t)((int64_t)dest_off - (int64_t)next_instr);
            memcpy(cb.b + instr_off + 2, &rel, 4);
        } else if (p->type == PATCH_JMP) {
            size_t instr_off = p->instr_offset;
            size_t next_instr = instr_off + 5;
            int32_t rel = (int32_t)((int64_t)dest_off - (int64_t)next_instr);
            memcpy(cb.b + instr_off + 1, &rel, 4);
        }
    }

    size_t total = cb.len;
    void *mem = alloc_exec(total);
    if (!mem) goto fail;
    memcpy(mem, cb.b, total);
    if (make_exec(mem, total) != 0) goto fail_mem;

    JITUnit *u = malloc(sizeof(JITUnit));
    if (!u) goto fail_mem;
    u->code = mem; u->size = total; u->fn = (int (*)(VM*))mem;

    if (cb.b) {
        volatile uint8_t *p = cb.b;
        for (size_t i = 0; i < cb.len; ++i) p[i] = 0;
        free(cb.b);
    }
    free(pc_to_out);
    if (patches) free(patches);
    return u;

fail_mem:
#ifdef _WIN32
    VirtualFree(mem, 0, MEM_RELEASE);
#else
    {
        size_t pagesz = (size_t)sysconf(_SC_PAGESIZE);
        size_t round = (total + pagesz - 1) & ~(pagesz - 1);
        munmap(mem, round);
    }
#endif
fail:
    if (cb.b) {
        volatile uint8_t *p = cb.b;
        for (size_t i = 0; i < cb.len; ++i) p[i] = 0;
        free(cb.b);
    }
    if (pc_to_out) free(pc_to_out);
    if (patches) free(patches);
    return NULL;
}

