# System Call Hooking and Logging

**Advanced UNIX Programming — Homework 1**  
**Language / Tools:** C, x86-64 Assembly, Linux System Calls, LD_PRELOAD, dlmopen, Capstone

## Overview

This project implements a **zpoline-inspired system call interception framework** for x86-64 Linux, together with a logging library that observes file and network activity in an existing program.

Instead of modifying the program on disk or changing the kernel, the framework injects a shared library at startup and redirects system calls by rewriting instructions in the process's executable memory.

The project was developed in stages, from constructing an executable trampoline to integrating a separate, configurable hook library. A major challenge was handling the transition between patched machine instructions, assembly code, and C handlers while preserving the program's execution state.

## Implementation Highlights

- **Runtime instruction rewriting:** Inspected executable memory regions through `/proc/self/maps`, used Capstone to locate `syscall` instructions, and replaced them with `call *%rax` (`0xFF 0xD0`). Temporarily changed page permissions using `mprotect` and restored executable permissions afterward.

- **Low-address trampoline:** Used a shared-library constructor to map a trampoline at virtual address `0x0`. A NOP-filled entry region and jump stub redirect execution to an assembly handler without modifying the original executable file.

- **Assembly-to-C syscall forwarding:** Implemented a trampoline that saves and restores registers, adjusts stack alignment before calling C, and forwards the original syscall arguments and number to a handler. A raw syscall entry point allows the handler to invoke the intended kernel operation.

- **Isolated hook loading:** Used `dlmopen(LM_ID_NEWLM, ...)` to load the hook library in a separate linker namespace, reducing recursive interception when the hook itself calls libc functions. The `__hook_init` interface connects the hook to the raw syscall function.

- **System call logging:** Implemented a `logger.so` hook for `openat`, `read`, `write`, `connect`, and `execve`. The logger reports syscall arguments and return values, escapes non-printable data, truncates displayed read/write content to 32 bytes, and formats IPv4, IPv6, and UNIX-domain socket addresses. `execve` is logged before execution because a successful call replaces the process image.

## Architecture

```text
Target Program
      |
      | LD_PRELOAD
      v
libzpoline.so
      |
      +-- Map low-address trampoline
      +-- Disassemble executable memory
      +-- Rewrite syscall instructions
      +-- Load hook library using dlmopen
      |
      v
Patched call *%rax
      |
      v
Assembly Trampoline
      |
      v
C Handler
      |
      v
logger.so Hook
      |
      v
Original System Call
```

## Build and Run

**Requirements:** x86-64 Linux, GCC, and the Capstone development library.

The trampoline requires mapping virtual address zero. In an isolated VM, the course environment was configured using:

```bash
sudo sysctl -w vm.mmap_min_addr=0
```

Build the final interception library and logger:

```bash
make libzpoline.so logger.so
```

Run a program with system call logging:

```bash
LD_PRELOAD="$PWD/libzpoline.so" LIBZPHOOK="$PWD/logger.so" /bin/cat /etc/hostname
```

The logger writes intercepted system call information to standard error.

**Note:** This implementation is intended for an isolated educational environment. Lowering `mmap_min_addr` weakens an operating-system security protection; restore the VM's original setting after testing.

## Source Files

| File | Description |
| --- | --- |
| `trampoline.c` | Initial trampoline mapping and redirection experiment |
| `step2.c` | Early syscall rewriting and output-transformation hook |
| `step3.c` | Final initialization library, syscall rewriting, trampoline, and dynamic hook loading |
| `logger.c` | File and network system call logging |
| `Makefile` | Build configuration |

## What I Learned

This project provided hands-on experience with **runtime binary instrumentation, virtual memory permissions, dynamic linking, and the x86-64 calling convention**.

It also demonstrated how low-level implementation details—particularly register preservation, stack alignment, and interactions with libc—can affect the correctness and stability of an entire application.

## References

- [Advanced UNIX Programming — HW1](https://md.zoolab.org/s/BQqWDSm9k)
- [zpoline — USENIX ATC 2023](https://www.usenix.org/conference/atc23/presentation/yasukata)
