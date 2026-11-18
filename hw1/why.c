#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#define LOG_PREFIX "libzpoline.so.2: "
#define LOG_ERROR "ERROR: "
#define NOP 0x90
#define PTR(byte) ((uint8_t *)byte)

extern int64_t trigger_syscall(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx, int64_t r8, int64_t r9, int64_t id);
extern void trampoline(void);


typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
static syscall_hook_fn_t hooked_syscall = NULL;

static void *__allocate__(void *addr, size_t *s) {
    long long size = sysconf(_SC_PAGE_SIZE);
    if(size == -1) {
        fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to get page size.\n");
        exit(1);
    }
    *s += (size - *s % size);
    void *ptr = mmap(addr, *s, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0x0);
    if(ptr == MAP_FAILED) {
        fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to allocate memory.\n");
        exit(1);
    }
    return ptr;
}

static void __free__(void *ptr, size_t size) {
    int err = munmap(ptr, size);
    if(err == -1) {
        fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to free memory.\n");
        exit(1);
    }
}



int64_t __handle__(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx, int64_t r8, int64_t r9, int64_t id) {


    if (hooked_syscall == NULL) {
        return trigger_syscall(rdi, rsi, rdx, rcx, r8, r9, id);
    }

    else{ 
        return  hooked_syscall(rdi, rsi, rdx, rcx, r8, r9, id);
    }
}



void load_hook_library() {
    const char *hook_lib = getenv("LIBZPHOOK");

    void *handle = dlmopen(LM_ID_NEWLM, hook_lib, RTLD_LAZY);

    void (*hook_init)(const syscall_hook_fn_t, syscall_hook_fn_t *) = 
            (void (*)(syscall_hook_fn_t, syscall_hook_fn_t*))dlsym(handle, "__hook_init");


    hook_init(trigger_syscall, &hooked_syscall);

    // 確保 hooked_syscall 有正確的指向
    if (!hooked_syscall) {
        hooked_syscall = trigger_syscall;
    }
    
}

void __raw_asm(void)
{
    asm volatile(
        "trampoline: \t\n"
            "push %rbp \t\n"
            "mov %rsp, %rbp \t\n"
            
            "push %r10 \t\n"
            "push %r9 \t\n"
            "push %r8 \t\n"
            "push %rdi \t\n"
            "push %rsi \t\n"
            "push %rdx \t\n"
            "push %r12 \t\n"

            "mov %rsp, %r12 \t\n"
            "mov $0xfffffffffffffff0, %r11 \t\n"
            "and %r11, %rsp \t\n"
            "sub %rsp, %r12 \t\n"

            
            "sub $16, %rsp \t\n"

            "push 136(%rbp) \t\n"
            "push %rax \t\n"
            "mov %r10, %rcx \t\n"
            "call __handle__ \t\n"

            "add $32, %rsp \t\n"
            "add %r12, %rsp \t\n"

            "pop %r12 \t\n"
            "pop %rdx \t\n"
            "pop %rsi \t\n"
            "pop %rdi \t\n"
            "pop %r8 \t\n"
            "pop %r9 \t\n"
            "pop %r10 \t\n"
            "leave \t\n"
            "add $128, %rsp \n\t"
            "ret \t\n"
    );

    asm volatile(
        "trigger_syscall: \t\n"
            
            "mov %rcx, %r10 \t\n"
            "syscall \t\n"
            "ret \t\n"
    );
}

static void *__find_region__(size_t *r) {
    uintptr_t (*collection)[2] = NULL;
    size_t temp = 0, size = 0;
    char *line = NULL;
    ssize_t n;

    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL) {
        fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to load running processes.\n");
        exit(1);
    }

    while((n = getline(&line, &size, f)) != -1) {
        char *addr_range = strtok(line, " \t\n");
        char *perms = strtok(NULL, " \t\n");
        char *filename = NULL;
        char *token = NULL;
        while((token = strtok(NULL, " \t\n")) != NULL) {
            filename = token;
        }
        if(strstr(filename, "libzpoline.so") != NULL) {
            continue;
        }
        if(strcmp(perms, "r-xp") == 0) {
            temp++;
            collection = realloc(collection, temp * sizeof(*collection));
            char *addr = strtok(addr_range, "-");
            collection[temp - 1][0] = strtoul(addr, NULL, 16);
            addr = strtok(NULL, "-");
            collection[temp - 1][1] = strtoul(addr, NULL, 16);
        }
        free(line);
        line = NULL;
    }
    *r = temp;
    return collection;
}

static void __disassemble__(void) {
    csh h;
    cs_insn *instr;
    size_t range = 0;
    uintptr_t (*arr)[2] = __find_region__(&range);

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
        fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to open Capstone device.\n");
        exit(1);
    }
    if(cs_option(h, CS_OPT_SKIPDATA, CS_OPT_ON) != CS_ERR_OK) {
        fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to set Capstone options.\n");
        exit(1);
    }

    for(size_t i = 0; i < range; i++) {
        uintptr_t head = arr[i][0];
        uintptr_t tail = arr[i][1];
        if(mprotect((void *)head, tail - head, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to revise permission.\n");
            exit(1);
        }

        size_t count = cs_disasm(h, (uint8_t *)head, tail - head, head, 0, &instr);
        if(count == 0) {
            fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to disassemble.\n");
            exit(EXIT_FAILURE);
        }

        for(size_t i = 0; i < count; i++) {
            if(instr[i].id == X86_INS_SYSCALL) {
                *(uint16_t *)instr[i].address = 0xd0ff;
            }
        }
        cs_free(instr, count);

        if(mprotect((void *)head, tail - head, PROT_READ | PROT_EXEC) == -1) {
            fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to revise permission.\n");
            exit(1);
        }
    }
    cs_close(&h);
    free(arr);
    printf("disassemble complete!\n");
}

static void *current = NULL;
__attribute__((constructor)) static void __init__(void) {
    size_t offset = 0;
    if(current == NULL) {
        size_t size = 1024;
        current = __allocate__(0, &(size));
    }
    // nop
    for(int i = 0; i < 512; i++) {
        PTR(current)[i] = NOP;
    }
    offset += 512;

    

    // sub rsp 0x80
    PTR(current)[offset] = 0x48;
    PTR(current)[offset + 1] = 0x81;
    PTR(current)[offset + 2] = 0xec;
    PTR(current)[offset + 3] = 0x80;
    PTR(current)[offset + 4] = 0x00;
    PTR(current)[offset + 5] = 0x00;
    PTR(current)[offset + 6] = 0x00;
    offset += 7;

    // mov r11 trampoline
    PTR(current)[offset] = 0x49;
    PTR(current)[offset + 1] = 0xbb;
    for(int i = 0; i < 8; i++) {
        PTR(current)[offset + i + 2] = ((uintptr_t)trampoline >> (8 * i)) & 0xff;
    }
    offset += 10;

    // jmp r11
    PTR(current)[offset] = 0x41;
    PTR(current)[offset + 0x01] = 0xff;
    PTR(current)[offset + 0x02] = 0xe3;

    printf("disassembl!\n");
    __disassemble__();

    if(mprotect(current, 1024, PROT_READ | PROT_EXEC) == -1) {
        fprintf(stderr, LOG_PREFIX LOG_ERROR "Failed to revise permission.\n");
        exit(1);
    }

    load_hook_library();

}

__attribute__((destructor)) static void __end__(void){
    if(current != NULL) {
        __free__(current, 1024);
    }
}