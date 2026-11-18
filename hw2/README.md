# Instruction-Level Debugger (SDB)

**Advanced UNIX Programming — Homework 2**  
**Language / Tools:** C++, Linux ptrace, ELF, x86-64, Capstone

## Overview

I implemented a **command-line debugger for x86-64 Linux executables** that allows users to inspect and control program execution at the assembly-instruction level.

The debugger combines the Linux `ptrace` interface with ELF parsing and Capstone disassembly to support instruction stepping, software breakpoints, register inspection, memory patching, and system call tracing.

One of the main challenges was maintaining consistency between the debugger's internal state and the target process's actual memory and registers, particularly when handling software breakpoints and position-independent executables.

## Implementation Highlights

- **Process control with ptrace:** Created and traced child processes using `fork`, `PTRACE_TRACEME`, and `exec`. Managed execution and stop events through `waitpid`, `PTRACE_CONT`, and `PTRACE_SINGLESTEP`.

- **ELF and PIE support:** Parsed ELF headers to identify executable entry points and executable types. Inspected `/proc/<pid>/maps` to calculate runtime load addresses for PIE executables, and implemented relative-address breakpoints through `breakrva`.

- **Instruction disassembly:** Read executable memory through `/proc/<pid>/mem` and used Capstone to decode x86-64 instructions. When displaying instructions containing breakpoints, reconstructed the original bytes to avoid showing inserted trap instructions.

- **Software breakpoints:** Implemented `INT3` (`0xCC`) breakpoints using `PTRACE_PEEKTEXT` and `PTRACE_POKETEXT`. Maintained original instruction bytes and handled breakpoint insertion, deletion, restoration, and reinsertion during execution.

- **Register inspection and memory patching:** Used `PTRACE_GETREGS` to inspect general-purpose registers and implemented a `patch` command to modify target-process memory. Maintained breakpoint consistency when modified bytes overlapped existing breakpoints.

- **System call tracing:** Used `PTRACE_SYSCALL` and register state to observe system call execution, including syscall numbers and return values.

## Supported Commands

| Command | Description |
| --- | --- |
| `load <path>` | Load an executable for debugging |
| `si` | Execute a single instruction |
| `cont` | Continue execution until a breakpoint or termination |
| `break <address>` | Insert a breakpoint at an absolute address |
| `breakrva <offset>` | Insert a breakpoint relative to the loaded image base |
| `delete <id>` | Remove an existing breakpoint |
| `info break` | Display active breakpoints |
| `info reg` | Display CPU registers |
| `patch <address> <hexbytes>` | Modify bytes in the target process |
| `syscall` | Trace system call entry and exit |

## Build and Run

**Requirements:** x86-64 Linux, G++, and the Capstone development library.

Compile the debugger:

```bash
make
```

Launch with a target executable:

```bash
./sdb /path/to/program
```

Alternatively, launch the debugger first and load an executable interactively:

```text
$ ./sdb
(sdb) load ./hello
(sdb) info reg
(sdb) si
(sdb) break 0x401000
(sdb) cont
```

The breakpoint address above is illustrative and must correspond to a valid executable address in the target program.

## Source Files

| File | Description |
| --- | --- |
| `sdb.cpp` | Debugger implementation, including process control, ELF parsing, breakpoints, disassembly, and command handling |
| `Makefile` | Build configuration and Capstone linking |

## Scope

This project implements a single-process, instruction-level debugger for x86-64 Linux as part of an Advanced UNIX Programming course.

It focuses on instruction-level execution control and does not attempt to support advanced process-creation or image-replacement transitions such as `fork`, `clone`, and `execve`.

## What I Learned

Implementing a debugger strengthened my understanding of **process execution, ELF program loading, virtual memory addressing, software traps, and kernel-assisted process tracing**.

Working directly with machine instructions and live process memory helped connect operating-system concepts with the actual behavior of compiled executables.

## Reference

- [Advanced UNIX Programming — HW2](https://md.zoolab.org/s/-ZkLZrI1m)
