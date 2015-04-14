Title: pwnypack 0.6.0
Date: 2015-04-14 11:30
Author: doskop
Tags: pwnypack
Slug: pwnypack-0-6-0

We've just released version 0.6.0 of our CTF toolkit *pwnypack*.

Here's what has changed:

* Bugfixes (and travis-ci integration).
* [API documentation](http://pwnypack.readthedocs.org/) and docstrings.
* Cycle-find can read from stdin.
* Major refactoring of ELF class. It can now parse section headers, program
  headers, symbol tables and extract section, symbols.
* Major refactoring of Target class. It's no longer tied to ELF (ELF is still
  a subclass of Target though).
* A reghex compiler.
* Verifying ROP gadget finder.
* Disassembler functionality (based on ndisasm or capstone).
* A more
* The ability to redirect stderr to stdout in flow.ProcessChannel.
* The ability to create symlinks for commandline apps.
* New commandline apps:
    * `asm` to assemble from commandline.
    * `symbols` to list the symbol table of an ELF file.
    * `gadget` to find ROP gadgets in an ELF file.
    * `symbol-extract` to extract a symbol from an ELF file.
    * `symbol-disasm` to disassemble a symbol in an ELF file.

## Getting it

* `$ pip install -U pwnypack`
* [pypi](https://pypi.python.org/pypi/pwnypack/0.6.0)
* [GitHub](https://github.com/edibledinos/pwnypack/releases/tag/v0.6.0)
