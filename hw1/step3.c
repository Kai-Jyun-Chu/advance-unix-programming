#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t,int64_t,int64_t,int64_t,
                                     int64_t,int64_t,int64_t);

extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t,
                               int64_t, int64_t, int64_t);
static syscall_hook_fn_t hooked_syscall = NULL;


static void rewrite_syscall() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen maps");
        return;
    }

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perror("capstone open");
        fclose(fp);
        return;
    }

    if (cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON) != CS_ERR_OK) {
        perror("capstone option");
        cs_close(&handle);
        fclose(fp);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end;
        char perm[5];
        char path[256] = {0};

        int fields = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perm, path);

        if (fields < 3)
            continue;

        if (strstr(path, "[vdso]") || strstr(path, "[vsyscall]") || strstr(path, "libzpoline.so.2") || strstr(path, "libzpoline.so"))
            continue;

        if (perm[0] != 'r' || perm[2] != 'x')
            continue;

        size_t len = end - start;

        if (mprotect((void*)start, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            perror("mprotect");
            continue;
        }

        cs_insn *insn;
        size_t count = cs_disasm(handle, (uint8_t *)start, len, start, 0, &insn);
        if (count == 0) {
            fprintf(stderr, "Capstone disasm failed\n");
            continue;
        }

        for (size_t i = 0; i < count; i++) {
            if (insn[i].id == X86_INS_SYSCALL) {
                uint16_t *p = (uint16_t *)insn[i].address;
                *p = 0xd0ff;   // Overwrite syscall 
            }
        }

        cs_free(insn, count);

        if (mprotect((void*)start, len, PROT_READ | PROT_EXEC) != 0) {
            perror("mprotect restore");
            continue;
        }
    }

    cs_close(&handle);
    fclose(fp);
}

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx,
                int64_t r10, int64_t r8,  int64_t r9,
                int64_t rax)
{
    //ex6
    


    if(hooked_syscall == NULL){
        return trigger_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
        
    }else{
        return hooked_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    }
    
}


void __raw_asm() {
  asm volatile("trigger_syscall: \t\n"
               /* Write assembly to prepare arguments here */
               "mov 8(%rsp), %rax \t\n"

               "  mov %rcx, %r10\t\n"
               //"  mov 16(%rbp), %rax\t\n"

               "  syscall \t\n"
               "  ret \t\n");
}
__attribute__((naked))
static void trampoline(void) {

    asm volatile(
        //"sub  $8, %rsp\n\t"
        "push %rdi\n\t"
        "push %rsi\n\t"
        "push %rdx\n\t"
        "push %r10\n\t"
        "push %r8\n\t"
        "push %r9\n\t"
        //allign
        "mov %rsp, %r11\n\t"
        "and $0xF, %r11\n\t"
        "sub %r11, %rsp\n\t"
        "push %r11\n\t"
        //
        "mov %r10, %rcx\n\t"
        "push %rax\n\t"

        "call handler\n\t"

        "add $8, %rsp\n\t"
        "pop %r11\n\t"
        "add %r11, %rsp\n\t" // check allign

        "pop %r9\n\t"
        "pop %r8\n\t"
        "pop %r10\n\t"
        "pop %rdx\n\t"
        "pop %rsi\n\t"
        "pop %rdi\n\t"
        "ret"
    );
}
static void load_hook_lib(void)
{
    const char *so = getenv("LIBZPHOOK");
    if(!so) return;                              /* no hooks – fine   */

    void *h = dlmopen(LM_ID_NEWLM, so, RTLD_NOW|RTLD_LOCAL);
    if(!h){ fprintf(stderr,"dlmopen: %s\n",dlerror()); _exit(1); }

    void (*hook_init)(const syscall_hook_fn_t, syscall_hook_fn_t*);
    *(void**)&hook_init = dlsym(h,"__hook_init");
    if(!hook_init){fprintf(stderr,"no __hook_init\n"); _exit(1);}

    hook_init(trigger_syscall, &hooked_syscall);
    if(!hooked_syscall){
        hooked_syscall=trigger_syscall;
    }
}

/* runs automatically when the .so is loaded */
__attribute__((constructor))
static void init_trampoline(void)
{
    void *addr = mmap((void*)0x0, 1000,
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
    load_hook_lib();
}
