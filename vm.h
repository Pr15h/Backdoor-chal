#ifndef VM_H
#define VM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h> 
#ifndef VM_NUM_REGS
#define VM_NUM_REGS 16
#endif

#ifndef VM_MEM_SIZE
#define VM_MEM_SIZE (64 * 1024) 
#endif

#ifndef VM_CALLSTACK_MAX
#define VM_CALLSTACK_MAX 1024
#endif

#ifndef VM_DATASTACK_MAX
#define VM_DATASTACK_MAX 1024
#endif

typedef int64_t vm_word_t;
typedef uint8_t vm_byte_t;

enum {
    VM_OK = 0,
    VM_ERR_ALLOC = 1,
    VM_ERR_INVALID = 2,
    VM_ERR_DIV_ZERO = 3,
    VM_ERR_MEM_OOB = 4,
    VM_ERR_STACK_UNDERFLOW = 5,
    VM_ERR_STACK_OVERFLOW = 6,
    VM_ERR_CALLSTACK_OVERFLOW = 7,
    VM_ERR_CALLSTACK_UNDERFLOW = 8,
    VM_ERR_UNKNOWN_OPCODE = 9,
};

enum VM_Opcode {
    OP_HLT               = 0x00,
    OP_NOP               = 0x01,
    OP_MOV_REG_REG       = 0x02,
    OP_MOV_REG_IMM       = 0x03,
    OP_ADD               = 0x04,
    OP_SUB               = 0x05,
    OP_MUL               = 0x06,
    OP_DIV               = 0x07,
    OP_AND               = 0x08,
    OP_OR                = 0x09,
    OP_XOR               = 0x0A,
    OP_SHL               = 0x0B,
    OP_SHR               = 0x0C,
    OP_LOAD_REG_MEM      = 0x0D,
    OP_STORE_MEM_REG     = 0x0E,
    OP_JMP               = 0x0F,
    OP_JZ                = 0x10,
    OP_JNZ               = 0x11,
    OP_CMP               = 0x12,
    OP_CALL              = 0x13,
    OP_RET               = 0x14,
    OP_PRINT_REG         = 0x15,
    OP_PRINT_IMM         = 0x16,
    OP_PUSH_REG          = 0x17,
    OP_POP_REG           = 0x18,
};

typedef struct VM {
    vm_word_t regs[VM_NUM_REGS];    

    
    vm_byte_t *code;
    size_t code_size;

   
    vm_byte_t *mem;
    size_t mem_size;

  
    ssize_t callstack[VM_CALLSTACK_MAX];
    int callsp;

   
    vm_word_t datstack[VM_DATASTACK_MAX];
    int datsp;

    ssize_t pc;


    int ZF;
    int SF;

   
    int debug; 

    int last_error;

} VM;




int vm_init(VM *vm, const vm_byte_t *code, size_t code_size, int want_copy);

void vm_free(VM *vm);

int vm_run(VM *vm);

int vm_step(VM *vm);

int vm_load_program(VM *vm, const vm_byte_t *code, size_t code_size);

void vm_set_debug(VM *vm, int debug_on);

int vm_read_mem(VM *vm, size_t addr, vm_word_t *out);
int vm_write_mem(VM *vm, size_t addr, vm_word_t val);

int vm_last_error(VM *vm);

int vm_disasm_at(VM *vm, ssize_t pc, char *outbuf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif

