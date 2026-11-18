#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void trampoline_handler(void) {

    const char msg[] = "Hello from trampoline!\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
}

/* runs automatically when the .so is loaded */
__attribute__((constructor))
static void init_trampoline(void)
{
    /* map  0x0 */
    void *addr = mmap((void*)0x0, 4096,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                      -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap 0x0 failed");
        _exit(1);
    }


    memset(addr, 0x90, 512);               /* 0x90 = NOP */

    /* 3. at offset 512 build a tiny stub that jumps to trampoline_handler */
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

    void *target = (void*)trampoline_handler;
    memcpy(code + 6, &target, sizeof(void*));  /* write absolute address */

    /* done – leave the page executable */
}
