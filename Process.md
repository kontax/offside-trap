# Project process

## Building
Initially this was supposed to be a decryption packer, however due to the 
complexity I've looked at implementing a virtual machine instead. The first
steps were to outline the different steps necessary for the full program, 
which are as follows:

1. ELF extraction
2. Bytecode conversion
3. Virtual Machine
4. ELF modification

## Issues
- Had problem with initial idea so moved to this
- Capstone has disassembly issue with offset
- Have to figure out ELF internals in a lot of detail
