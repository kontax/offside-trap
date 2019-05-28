# Offside Trap
An ELF packer which converts a binary into runtime instructions. Would be good
if some kind of randomness could be implemented somehow, maybe with the instruction set. Seems a bit
unlikely though..

## Questions
* Does it work by replicating opcodes? Could be very slow if so.
* Syscalls for all syscalls?
* Perhaps only implement a subset of instructions to start.
* How do I embed the interpreter into the application?
    - Could be something like a read from memory to a file descriptor
    - Although that would mean the full program is still in memory, which is kinda useless
* Better option would just be to replace the program completely after analysis
* What language? Should encryption be used at all?
* What will it be written in?
* How will the text section be parsed?
* What will the form be, a standalone binary or compiler extension?
* How will randomness be implemented? Seems a bit of a stretch for a compiled program.
    - Random exection path - see kuang et al 2018
    - Multiple VMs as layers, different one each time
* Whole application or just select parts?

## Design

### ELF extraction
1. Locate text section in ELF binary
2. Parse function calls
    - Differentiate between dynamically loaded and internal
    - Search for preamble
3. Present choice of functions to protect
4. Disassemble specified functions and pass to converter

### Bytecode conversion
1. Retrieve each function from previous step
2. Convert each instruction to the virtual machine's opcodes
    - Note the syscalls and implement based on number
3. Replace original function with call to VM and reference to VM code

### Virtual machine
1. Register or stack based?
2. Initialisation step
3. Fetch, execute, decode
    - Dispatcher fetches opcode from memory
    - Translater converts it to machine code
    - Handler executes the result

### ELF repacker
1. Place the translated code into memory section (possibly encrypted)
2. Place VM code in another section
3. Replace references to translated code where original code was once
4. Use stub to point to VM handler in place of startup function

