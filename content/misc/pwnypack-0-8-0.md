Title: pwnypack 0.8.0
Date: 2016-05-17 18:22
Author: doskop
Tags: pwnypack
Slug: pwnypack-0-8-0

We've just released version 0.8.0 of our CTF toolkit *pwnypack*. And it's a pretty big release! Some of the highlights are:

### Major improvements in assembler support

We can now assemble nasm syntax, Intel syntax and AT&T syntax on X86 (32 and 64 bit) as well assembling ARM instructions. Currently several backends are available:

- [Keystone engine](http://www.keystone-engine.org) which is estimated to be released to the public in June 2016 can assemble all supported syntaxes on all supported platforms so it's the default and recommended assembler engine if it's available.

If keystone engine isn't available, several other tools will be used:

- `nasm` will be used to assemble X86 instructions using nasm syntax.
- `GNU binutils` will be used to assemble X86 instructions using Intel and AT&T syntax and it's used to assemble ARM instructions. *pwnypack* will look for most common binutils architecture and target names to find the right variant of binutils.

### Shellcode generator

Hot on the heels of the improved assembler support, we've created a system that allows you to describe shellcode in a cross-platform high-level declarative fashion. Additionally, it's possible to translate a sort of DSL within python to such an AST. Currently, there's support for Linux on X86 and ARM. Be sure to check out the [documentation](http://pwnypack.readthedocs.io/en/v0.8.0/pwnypack/shellcode.html).

### Cross-version marshal loader and bytecode tools

Did you ever encounter that annoyance when you're trying to [load a .pyc](http://pwnypack.readthedocs.io/en/v0.8.0/pwnypack/marshal.html#pwnypack.marshal.pyc_load) file for a challenge and you have no idea what version of python was used to compile it? And then trying to get that version of python working on your machine? Or maybe you've found some marshalled python data and you have no idea what version it came from? Well, *pwnypack* can now [load a wide variety of marshalled data](http://pwnypack.readthedocs.io/en/v0.8.0/pwnypack/marshal.html#pwnypack.marshal.marshal_load) (including code objects) independent of the version of python you're actually running and it can [disassemble](http://pwnypack.readthedocs.io/en/v0.8.0/pwnypack/bytecode.html#pwnypack.bytecode.disassemble) (and [assemble](http://pwnypack.readthedocs.io/en/v0.8.0/pwnypack/bytecode.html#pwnypack.bytecode.assemble)) python bytecode for various version of python. There's even an extension to the pickle\_call function that will allow you to actually [pickle a function](http://pwnypack.readthedocs.io/en/v0.8.0/pwnypack/pickle.html#pwnypack.pickle.pickle_func) which is then automatically invoked when it's unpickled.

### Changelog

Here's the curated changelog:

* Return empty list when trying to read non-existing .dynamic section.
* Don't print newline when piping the output of a gadget.
* Fix output of raw binary data on python 3.
* Add pwnypack extension for ipython.
* Add pwnypack jupyter notebook wrapper (pwnbook).
* Moved and renamed util.pickle\_call to pickle.pickle\_invoke.
* Added pickle\_func that pickles a function and its invocation.
* Added support for using GNU binutils to assemble AT&T and intel syntax.
* Added support for assembling/disassembling ARM using binutils/capstone.
* Use extras\_require to make capstone, paramiko and jupyter optional.
* Add Dockerfile for pwnypack shell and pwnbook.
* Fix interact on python 3 in Flow.
* Add python bytecode manipulation functions.
* Added shellcode generator for X86/X86\_64, ARM (+Thumb) and AArch64.
* Use keystone engine as assembler engine by default.
* Added xor mask finder.
* Added python independent marshal and .pyc loader.
* Fix internal escaping of reghex expressions.
* Allow wildcards when searching for ROP gadgets using assembly statements.

## Getting it

* `$ pip install --no-binary capstone -U pwnypack[all]`
* [pypi](https://pypi.python.org/pypi/pwnypack/0.8.0)
* [GitHub](https://github.com/edibledinos/pwnypack/releases/tag/v0.8.0)
