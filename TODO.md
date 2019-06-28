# TODO List

1. ~~Fix staticly compiled files~~ _note: encrypting some functions breaks it_
2. Work without -no-pie
3. ~~Fix limit on function count~~
4. Encrypt without symbols
5. Implement RC4
6. Modify the ELF parser
    a. Add program header and section header classes to the ELF class, and clean up the add segment code
    b. Add symbol tables to the main ELF class
    c. Add references to sections within segments, symbols within sections etc.
    d. Look at making symbols easier to work with
7. Re-encrypt functions on calling another function
