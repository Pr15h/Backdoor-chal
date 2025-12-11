#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "vm.h"


static int read_le(VM *vm, ssize_t pos, void *out, size_t n) {
    if (!vm) return VM_ERR_INVAL;
    if (pos < 0) return VM_ERR_OOB;
    if ((size_t)pos + n > vm->code_size) return VM_ERR_OOB;
    memcpy(out, vm->code + pos, n);
    return VM_OK;
}

static int read_u8(VM *vm, ssize_t pos, uint8_t *out) { return read_le(vm, pos, out, 1); }
static int read_s32(VM *vm, ssize_t pos, int32_t *out) { return read_le(vm, pos, out, 4); }
static int read_s64(VM *vm, ssize_t pos, int64_t *out) { return read_le(vm, pos, out, 8); }
static int read_u64(VM *vm, ssize_t pos, uint64_t *out) { return read_le(vm, pos, out, 8); }

static int mem_read_word(VM *vm, size_t addr, vm_word_t *out) {
    if (addr + VM_WORD_BYTES > vm->mem_size) { vm->last_error = VM_ERR_OOB; return VM_ERR_OOB; }
    memcpy(out, vm->mem + addr, VM_WORD_BYTES);
    return VM_OK;
}
static int mem_write_word(VM *vm, size_t addr, vm_word_t val) {
    if (addr + VM_WORD_BYTES > vm->mem_size) { vm->last_error = VM_ERR_OOB; return VM_ERR_OOB; }
    memcpy(vm->mem + addr, &val, VM_WORD_BYTES);
    return VM_OK;
}

static int push_reg(VM *vm, vm_word_t val) {
    vm_word_t sp = vm->regs[RSP];
    if (sp < VM_WORD_BYTES) { vm->last_error = VM_ERR_STACK_OVERFLOW; return VM_ERR_STACK_OVERFLOW; }
    sp -= VM_WORD_BYTES;
    vm->regs[RSP] = sp;
    return mem_write_word(vm, (size_t)sp, val);
}
static int pop_reg(VM *vm, vm_word_t *out) {
    vm_word_t sp = vm->regs[RSP];
    if (sp + VM_WORD_BYTES > vm->mem_size) { vm->last_error = VM_ERR_STACK_UNDERFLOW; return VM_ERR_STACK_UNDERFLOW; }
    int r = mem_read_word(vm, (size_t)sp, out);
    if (r != VM_OK) return r;
    vm->regs[RSP] = sp + VM_WORD_BYTES;
    return VM_OK;
}

int vm_init(VM *vm, const vm_byte_t *code, size_t code_size, int want_copy) {
    if (!vm) return VM_ERR_INVAL;
    memset(vm, 0, sizeof(*vm));

    const size_t default_mem = 256 * 1024; 

    if (code && code_size > 0) {
        if (want_copy) {
            vm->code = (vm_byte_t*)malloc(code_size);
            if (!vm->code) return VM_ERR_NO_MEM;
            memcpy(vm->code, code, code_size);
            vm->owns_code = 1;
        } else {
            vm->code = (vm_byte_t*)code;
            vm->owns_code = 0;
        }
        vm->code_size = code_size;
    } else {
        vm->code = NULL;
        vm->code_size = 0;
        vm->owns_code = 0;
    }

    vm->mem = (vm_byte_t*)malloc(default_mem);
    if (!vm->mem) {
        if (vm->owns_code && vm->code) free(vm->code);
        return VM_ERR_NO_MEM;
    }
    vm->mem_size = default_mem;
    vm->owns_mem = 1;
    memset(vm->mem, 0, vm->mem_size);

    for (int i = 0; i < VM_NUM_REGS; ++i) vm->regs[i] = 0;
    vm->regs[RSP] = vm->mem_size;

    vm->pc = 0;
    vm->callsp = -1;
    vm->ZF = 0;
    vm->SF = 0;
    vm->debug = 0;
    vm->last_error = VM_OK;

    magic_init(0);

    for (int i = 0; i < 40; ++i) vm->holes[i] = 0;

    return VM_OK;
}

void vm_free(VM *vm) {
    if (!vm) return;
    if (vm->mem && vm->owns_mem) { free(vm->mem); vm->mem = NULL; vm->mem_size = 0; vm->owns_mem = 0; }
    if (vm->code && vm->owns_code) { free(vm->code); vm->code = NULL; vm->code_size = 0; vm->owns_code = 0; }
    memset(vm, 0, sizeof(*vm));
}

int vm_load_program(VM *vm, const vm_byte_t *code, size_t code_size) {
    if (!vm) return VM_ERR_INVAL;
    if (vm->code && vm->owns_code) { free(vm->code); vm->code = NULL; vm->code_size = 0; vm->owns_code = 0; }
    if (!code || code_size == 0) { vm->code = NULL; vm->code_size = 0; return VM_OK; }
    vm->code = (vm_byte_t*)malloc(code_size);
    if (!vm->code) return VM_ERR_NO_MEM;
    memcpy(vm->code, code, code_size);
    vm->code_size = code_size;
    vm->owns_code = 1;
    vm->pc = 0;
    vm->callsp = -1;
    vm->ZF = vm->SF = 0;
    vm->last_error = VM_OK;
    return VM_OK;
}

void vm_set_debug(VM *vm, int debug_on) { if (!vm) return; vm->debug = debug_on ? 1 : 0; }
int vm_last_error(VM *vm) { if (!vm) return VM_ERR_INVAL; return vm->last_error; }

int vm_read_mem(VM *vm, size_t addr, vm_word_t *out) { return mem_read_word(vm, addr, out); }
int vm_write_mem(VM *vm, size_t addr, vm_word_t val) { return mem_write_word(vm, addr, val); }

int vm_step(VM *vm) {
    if (!vm) return VM_ERR_INVAL;
    if (vm->pc < 0 || (size_t)vm->pc >= vm->code_size) { vm->last_error = VM_ERR_OOB; return vm->last_error; }

    uint8_t op = vm->code[vm->pc];
    ssize_t next = vm->pc + 1;

    if (vm->debug) {
    }

    switch (op) {
    case OP_MAGIC: {
        uint8_t site = 0;
        if (read_u8(vm, next, &site) != VM_OK) {
        vm->last_error = VM_ERR_OOB;
        return vm->last_error;
        }
        next += 1;

        if (site == OP_MAGIC_SITE_HOLES) {
        magic_generate_holes(vm->holes, 40);

        vm->pc = next;
        return VM_OK;
        }

        magic_expand_and_execute((void*)vm);
        vm->pc = next;
        return VM_OK;
    }
        case OP_NOP:
            vm->pc = next;
            return VM_OK;

        case OP_HALT:
            vm->pc = next;
            vm->last_error = VM_ERR_HALT;
            return VM_ERR_HALT;

        case OP_MOV_RI: {
            uint8_t rd;
            if (read_u8(vm, next, &rd) != VM_OK) { vm->last_error = VM_ERR_OOB; return vm->last_error; }
            next += 1;
            uint64_t imm;
            if (read_u64(vm, next, &imm) != VM_OK) { vm->last_error = VM_ERR_OOB; return vm->last_error; }
            next += 8;
            if (rd >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            vm->regs[rd] = (vm_word_t)imm;
            vm->ZF = (vm->regs[rd] == 0);
            vm->SF = ((int64_t)vm->regs[rd] < 0);
            vm->pc = next;
            return VM_OK;
        }

        case OP_MOV_RR: {
            uint8_t rd, rs;
            if (read_u8(vm, next, &rd) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_u8(vm, next, &rs) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (rd >= VM_NUM_REGS || rs >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            vm->regs[rd] = vm->regs[rs];
            vm->ZF = (vm->regs[rd] == 0);
            vm->SF = ((int64_t)vm->regs[rd] < 0);
            vm->pc = next;
            return VM_OK;
        }

        case OP_ADD:
        case OP_SUB:
        case OP_MUL:
        case OP_DIV: {
            uint8_t rd, ra, rb;
            if (read_u8(vm, next, &rd) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_u8(vm, next, &ra) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_u8(vm, next, &rb) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (rd >= VM_NUM_REGS || ra >= VM_NUM_REGS || rb >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            int64_t a = (int64_t)vm->regs[ra];
            int64_t b = (int64_t)vm->regs[rb];
            int64_t r = 0;
            if (op == OP_ADD) r = a + b;
            else if (op == OP_SUB) r = a - b;
            else if (op == OP_MUL) r = a * b;
            else if (op == OP_DIV) {
                if (b == 0) { vm->last_error = VM_ERR_DIV_BY_ZERO; return vm->last_error; }
                r = a / b;
            }
            vm->regs[rd] = (vm_word_t)r;
            vm->ZF = (vm->regs[rd] == 0);
            vm->SF = ((int64_t)vm->regs[rd] < 0);
            vm->pc = next;
            return VM_OK;
        }

        case OP_LOAD: {
            uint8_t rd, base;
            int32_t off;
            if (read_u8(vm, next, &rd) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_u8(vm, next, &base) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_s32(vm, next, &off) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 4;
            if (rd >= VM_NUM_REGS || base >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            int64_t eff = (int64_t)vm->regs[base] + (int64_t)off;
            if (eff < 0 || (size_t)eff + VM_WORD_BYTES > vm->mem_size) { vm->last_error = VM_ERR_OOB; return vm->last_error; }
            vm_word_t val;
            if (mem_read_word(vm, (size_t)eff, &val) != VM_OK) return vm->last_error;
            vm->regs[rd] = val;
            vm->ZF = (val == 0);
            vm->SF = ((int64_t)val < 0);
            vm->pc = next;
            return VM_OK;
        }

        case OP_STORE: {
            uint8_t rs, base;
            int32_t off;
            if (read_u8(vm, next, &rs) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_u8(vm, next, &base) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_s32(vm, next, &off) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 4;
            if (rs >= VM_NUM_REGS || base >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            int64_t eff = (int64_t)vm->regs[base] + (int64_t)off;
            if (eff < 0 || (size_t)eff + VM_WORD_BYTES > vm->mem_size) { vm->last_error = VM_ERR_OOB; return vm->last_error; }
            if (mem_write_word(vm, (size_t)eff, vm->regs[rs]) != VM_OK) return vm->last_error;
            vm->pc = next;
            return VM_OK;
        }

        case OP_PUSH: {
            uint8_t rs;
            if (read_u8(vm, next, &rs) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (rs >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            int r = push_reg(vm, vm->regs[rs]);
            if (r != VM_OK) return vm->last_error = r;
            vm->pc = next;
            return VM_OK;
        }

        case OP_POP: {
            uint8_t rd;
            if (read_u8(vm, next, &rd) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (rd >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            vm_word_t v;
            if (pop_reg(vm, &v) != VM_OK) return vm->last_error;
            vm->regs[rd] = v;
            vm->pc = next;
            return VM_OK;
        }

        case OP_JMP:
        case OP_JZ:
        case OP_JNZ:
        case OP_CALL: {
            int64_t target;
            if (read_s64(vm, next, &target) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 8;
            if (target < 0 || (size_t)target >= vm->code_size) { vm->last_error = VM_ERR_OOB; return vm->last_error; }
            if (op == OP_JMP) {
                vm->pc = (ssize_t)target;
                return VM_OK;
            } else if (op == OP_JZ) {
                if (vm->ZF) { vm->pc = (ssize_t)target; return VM_OK; }
                vm->pc = next;
                return VM_OK;
            } else if (op == OP_JNZ) {
                if (!vm->ZF) { vm->pc = (ssize_t)target; return VM_OK; }
                vm->pc = next;
                return VM_OK;
            } else { 
                if (vm->callsp + 1 >= (int)(sizeof(vm->callstack)/sizeof(vm->callstack[0]))) { vm->last_error = VM_ERR_CALLSTACK_OVERFLOW; return vm->last_error; }
                vm->callstack[++vm->callsp] = next;
                vm->pc = (ssize_t)target;
                return VM_OK;
            }
        }

        case OP_RET: {
            if (vm->callsp < 0) { vm->last_error = VM_ERR_CALLSTACK_UNDERFLOW; return vm->last_error; }
            ssize_t ret = vm->callstack[vm->callsp--];
            if (ret < 0 || (size_t)ret > vm->code_size) { vm->last_error = VM_ERR_OOB; return vm->last_error; }
            vm->pc = ret;
            return VM_OK;
        }

        case OP_CMP_RR: {
            uint8_t ra, rb;
            if (read_u8(vm, next, &ra) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (read_u8(vm, next, &rb) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (ra >= VM_NUM_REGS || rb >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            int64_t a = (int64_t)vm->regs[ra];
            int64_t b = (int64_t)vm->regs[rb];
            int64_t r = a - b;
            vm->ZF = (r == 0);
            vm->SF = (r < 0);
            vm->pc = next;
            return VM_OK;
        }

        case OP_PRINT_R: {
            uint8_t rs;
            if (read_u8(vm, next, &rs) != VM_OK) return vm->last_error = VM_ERR_OOB;
            next += 1;
            if (rs >= VM_NUM_REGS) { vm->last_error = VM_ERR_INVAL; return vm->last_error; }
            printf("%" PRId64 "\n", (int64_t)vm->regs[rs]);
            vm->pc = next;
            return VM_OK;
        }

        default:
            vm->last_error = VM_ERR_BAD_OPCODE;
            return vm->last_error;
    }
}

int vm_run(VM *vm) {
    if (!vm) return VM_ERR_INVAL;
    int r;
    while (1) {
        r = vm_step(vm);
        if (r == VM_OK) continue;
        if (r == VM_ERR_HALT) return VM_ERR_HALT;
        return r;
    }
}

int vm_disasm_at(VM *vm, ssize_t pc, char *outbuf, size_t buflen) {
    if (!vm || !outbuf) return VM_ERR_INVAL;
    if (pc < 0 || (size_t)pc >= vm->code_size) return VM_ERR_OOB;
    uint8_t op = vm->code[pc];
    ssize_t cur = pc + 1;
    int n = 0;
    switch (op) {
        case OP_NOP: n = snprintf(outbuf, buflen, "NOP"); return 1;
        case OP_HALT: n = snprintf(outbuf, buflen, "HALT"); return 1;
        case OP_MOV_RI: {
            uint8_t rd; uint64_t imm;
            if (read_u8(vm, cur, &rd) != VM_OK) return VM_ERR_OOB; cur+=1;
            if (read_u64(vm, cur, &imm) != VM_OK) return VM_ERR_OOB;
            return (int)(1 + 1 + 8);
        }
        case OP_MOV_RR: return 1 + 1 + 1;
        case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: return 1 + 3;
        case OP_LOAD: case OP_STORE: return 1 + 1 + 1 + 4;
        case OP_PUSH: case OP_POP: return 1 + 1;
        case OP_JMP: case OP_JZ: case OP_JNZ: case OP_CALL: return 1 + 8;
        case OP_RET: return 1;
        case OP_CMP_RR: return 1 + 1 + 1;
        case OP_PRINT_R: return 1 + 1;
        default:
            return 1;
    }
}
