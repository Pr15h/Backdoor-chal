#ifndef VM_H
#define VM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

typedef uint8_t  vm_byte_t;
typedef uint64_t vm_word_t;

#define VM_WORD_BYTES (sizeof(vm_word_t))

#define VM_NUM_REGS 16

typedef enum {
    RAX = 0,
    RBX = 1,
    RCX = 2,
    RDX = 3,
    RSI = 4,
    RDI = 5,
    RBP = 6,
    RSP = 7,
    R8  = 8,
    R9  = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15
} reg_t;

typedef enum {
    VM_OK = 0,
    VM_ERR_OOB = -1,
    VM_ERR_STACK_UNDERFLOW = -2,
    VM_ERR_STACK_OVERFLOW = -3,
    VM_ERR_CALLSTACK_OVERFLOW = -4,
    VM_ERR_CALLSTACK_UNDERFLOW = -5,
    VM_ERR_BAD_OPCODE = -6,
    VM_ERR_DIV_BY_ZERO = -7,
    VM_ERR_HALT = 1,  
    VM_ERR_NO_MEM = -8,
    VM_ERR_INVAL = -9
} vm_error_t;

typedef enum {
    OP_NOP = 0x00,
    OP_HALT = 0x01,

   
    OP_MOV_RI = 0x10, 
    OP_MOV_RR = 0x11,
    OP_ADD = 0x20,      
    OP_SUB = 0x21,
    OP_MUL = 0x22,
    OP_DIV = 0x23,
    OP_LOAD = 0x30,
    OP_STORE = 0x31, 
    OP_PUSH = 0x40,     
    OP_POP  = 0x41,      
    OP_JMP  = 0x50,      
    OP_JZ   = 0x51,      
    OP_JNZ  = 0x52,      
    OP_CALL = 0x53,     
    OP_RET  = 0x54,      
    OP_CMP_RR = 0x60,    

    OP_PRINT_R = 0x70, 

    OP_DB = 0xFF
} opcode_t;

typedef struct VM {

    vm_word_t regs[VM_NUM_REGS];

    vm_byte_t *code;
    size_t code_size;

    vm_byte_t *mem;
    size_t mem_size;

    int owns_code;
    int owns_mem;


    ssize_t callstack[1024];
    int callsp;

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
