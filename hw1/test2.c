#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t,
                               int64_t, int64_t, int64_t);

static const char leet_tbl[256] = {
    ['0'] = 'o', ['1'] = 'i', ['2'] = 'z', ['3'] = 'e',
    ['4'] = 'a', ['5'] = 's', ['6'] = 'g', ['7'] = 't'
};

static void rewrite_syscall() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen maps");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end;
        char perm[5];
        char path[256] = {0};

        // Try to parse optional path field too
        int fields = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perm, path);

        if (fields < 3)
            continue;

        // Ignore special mappings
        if (strstr(path, "[vdso]") || strstr(path, "[vsyscall]") || strstr(path, "libzpoline.so.2"))
            continue;

        // Only rewrite readable + executable pages (e.g., "r-xp")
        if (perm[0] != 'r' || perm[2] != 'x')
            continue;

        size_t len = end - start;

        if (mprotect((void*)start, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            perror("mprotect");
            continue;
        }

        unsigned char *p = (unsigned char*)start;
        for (size_t i = 0; i < len - 1; ++i) {
            if (p[i] == 0x0f && p[i+1] == 0x05) {  // syscall
                p[i] = 0xff; // call *%rax
                p[i+1] = 0xd0;
            }
        }
    }

    fclose(fp);
}

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx,
                int64_t r10, int64_t r8,  int64_t r9,
                int64_t rax)
{
    if(rax == 1 && rdi == 1){
        size_t len = (size_t)rdx;
        char *src  = (char*)rsi;
        char *tmp  = malloc(len);
        if (!tmp)  /* OOM fallback */ return trigger_syscall(rdi,rsi,rdx,r10,r8,r9,rax);

        for (size_t i = 0; i < len; ++i) {
            unsigned char c = src[i];
            tmp[i] = leet_tbl[c] ? leet_tbl[c] : c;
        }
        int64_t ret = trigger_syscall(rdi, (int64_t)tmp, rdx, r10, r8, r9, rax);
        free(tmp);
        return ret;
    }
    return trigger_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
}


void __raw_asm() {
  asm volatile("trigger_syscall: \t\n"
               /* Write assembly to prepare arguments here */
               "mov %rcx, %r10\t\n"
               "  mov 16(%rbp), %rax\t\n"
               "  syscall \t\n"
               "  ret \t\n");
}

static void trampoline(void) {

    //const char msg[] = "Hello from trampoline!\n";
    //write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    asm volatile(

           /*
        "push %rdi\n\t"
        "push %rsi\n\t"
        "push %rdx\n\t"
        "push %r10\n\t"
        "push %r8\n\t"
        "push %r9\n\t"

        "sub $8, %rsp\n\t" 
*/
        "push %rax\n\t"
        "mov %r10, %rcx\n\t"
        "call handler\n\t"

        "add $8, %rsp\n\t"
        /*
        "add $8, %rsp\n\t"
        "pop %r9\n\t"
        "pop %r8\n\t"
        "pop %r10\n\t"
        "pop %rdx\n\t"
        "pop %rsi\n\t"
        "pop %rdi\n\t"


        "ret\n\t"*/
    );
}

/* runs automatically when the .so is loaded */
__attribute__((constructor))
static void init_trampoline(void)
{
    void *addr = mmap((void*)0x0, 4096,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                      -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap 0x0 failed");
        _exit(1);
    }

    memset(addr, 0x90, 512);               /* 0x90 = NOP */

    unsigned char *code = (unsigned char*)addr + 512;

    /*
       ff 25 00 00 00 00      jmp QWORD PTR [rip+0]   (6 bytes)
       <8-byte absolute addr>                         (8 bytes)
    */
    code[0] = 0xFF;
    code[1] = 0x25;
    code[2] = 0x00;
    code[3] = 0x00;
    code[4] = 0x00;
    code[5] = 0x00;

    void *target = (void*)trampoline;
    memcpy(code + 6, &target, sizeof(void*));  /* write absolute address */
    rewrite_syscall();
}
