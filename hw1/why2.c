#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <link.h>
#include <dlfcn.h>
#include <errno.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#define LOG_PREFIX "libzpoline.so.2: "
#define LOG_ERROR "ERROR: "
#define NOP 0x90
#define PTR(byte) ((uint8_t *)byte)

extern int64_t trigger_syscall(int64_t,int64_t,int64_t,int64_t,int64_t,int64_t,int64_t);

void __raw_asm() {
    asm volatile(
        "trigger_syscall: \n\t"
        "mov %rcx, %r10\n\t"
        "mov 16(%rbp), %rax\n\t"
        "syscall\n\t"
        "ret"
    );
}

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
static syscall_hook_fn_t hooked_syscall = NULL;

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx, int64_t r8, int64_t r9, int64_t rax) {
    if (hooked_syscall == NULL) {
        return trigger_syscall(rdi, rsi, rdx, rcx, r8, r9, rax);
    }
    return hooked_syscall(rdi, rsi, rdx, rcx, r8, r9, rax);
}

__attribute__((naked))
void trampoline_func() {
    asm volatile(
        "push %rdi\n\t"
        "push %rsi\n\t"
        "push %rdx\n\t"
        "push %r10\n\t"
        "push %r8\n\t"
        "push %r9\n\t"

        "mov %rsp, %r11\n\t"
        "and $0xF, %r11\n\t"
        "sub %r11, %rsp\n\t"
        "push %r11\n\t"

        "mov %r10, %rcx\n\t"
        "push %rax\n\t"
        "call handler\n\t"

        "add $0x8, %rsp\n\t"
        "pop %r11\n\t"
        "add %r11, %rsp\n\t"

        "pop %r9\n\t"
        "pop %r8\n\t"
        "pop %r10\n\t"
        "pop %rdx\n\t"
        "pop %rsi\n\t"
        "pop %rdi\n\t"
        "ret"
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
}



// replace all syscall (0f 05) with call *%rax (ff d0)
__attribute__((constructor))
void patch_syscalls() {
    void* addr = mmap((void*)0x0, 0x1000,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                    -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // 填滿前 512 bytes 的 nop
    memset(addr, 0x90, 512);
    // 在 offset 512 開始寫 trampoline
    unsigned char *trampoline = (unsigned char *)addr + 512;


    //jmp QWORD PTR [rip+0]
    trampoline[0] = 0xFF;
    trampoline[1] = 0x25;
    trampoline[2] = 0x00;                      
    trampoline[3] = 0x00;
    trampoline[4] = 0x00;                      
    trampoline[5] = 0x00;                      
    void (*trampoline_ptr)() = trampoline_func;
    *(uint64_t*)(trampoline + 6) = (uint64_t)trampoline_ptr;
    

    __disassemble__();
    // FILE *maps = fopen("/proc/self/maps", "r");
    // if (!maps) return;

    // char line[256];
    // while (fgets(line, sizeof(line), maps)) {
    //     uintptr_t start, end;
    //     char perm[5];
    //     if (sscanf(line, "%lx-%lx %4s", &start, &end, perm) != 3) {
    //         continue;
    //     }
    //     if(start == 0)continue;
    //     if (strchr(perm, 'r') == NULL) continue; // must be readable
    //     if (strchr(perm, 'x') == NULL) continue; // must be executable
    //     if (strstr(line, "[vdso]") || strstr(line, "[vsyscall]") || strstr(line, "libzpoline.so")) {
    //         continue; // 跳過 vdso 和 vsyscall 區段
    //     }
    //     printf("line passed: %s\n", line);
        
    //     for (uintptr_t addr = start; addr + 1 < end; ++addr) {
    //         unsigned char *p = (unsigned char *)addr;
    //         if (p[0] == 0x0f && p[1] == 0x05) {
    //             // make page writable temporarily
    //             uintptr_t page = addr & ~(0x1000 - 1);
    //             mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    //             p[0] = 0xff;
    //             p[1] = 0xd0;  // call *%rax
    //             mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
    //         }
    //     }
    // }
    // fclose(maps);

    const char *libname = getenv("LIBZPHOOK");
    if (!libname) {
        fprintf(stderr, "[zpoline] LIBZPHOOK not set\n");
        return;
    }
    void *handle = dlmopen(LM_ID_NEWLM, libname, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "[zpoline] Failed to load hook library: %s\n", dlerror());
        return;
    }
    void (*hook_init)(const syscall_hook_fn_t, syscall_hook_fn_t *);
    hook_init = (void (*)(const syscall_hook_fn_t, syscall_hook_fn_t *)) dlsym(handle, "__hook_init");

    if (!hook_init) {
        fprintf(stderr, "[zpoline] __hook_init not found: %s\n", dlerror());
        return;
    }
    hooked_syscall = trigger_syscall; // 預設 fallback
    hook_init(trigger_syscall, &hooked_syscall);
}