# TODO List

1. ~~Fix staticly compiled files~~ _note: encrypting some functions breaks it_
2. ~~Work without -no-pie~~
    a. ~~Modify loader.nasm to point to [rip-(instructions so far)-(decrypt_offset)+(func_offset)~~
    b. ~~Change table in poc.py to use offsets~~
3. ~~Fix limit on function count~~
4. ~~Encrypt without symbols~~
5. Implement RC4
6. ~~Modify the ELF parser~~
    1. ~~Add program header and section header classes to the ELF class, and clean up the add segment code~~
    2. ~~Add symbol tables to the main ELF class~~
    3. ~~Add references to sections within segments, symbols within sections etc.~~
    4. ~~Look at making symbols easier to work with~~
7. Re-encrypt functions on calling another function
8. Reduce size (or need completely) of table
9. Encrypt bytes before adding them to the table
10. ~~Remove the necessity of making the text section writable (entry doesn't work on PIE)~~
11. ~~Find some malware~~
    1. ~~http://contagiodump.blogspot.com/~~
    2. ~~https://virusshare.com/~~
    3. ~~https://developers.virustotal.com/~~
12. ~~Figure out why there are differences in the outputs of cal~~
13. Requirements:
    1. python
    2. virtualenv
    3. nasm
    4. radare2
14. Load program header into new segment
    1. Figure out how to set original entry point for PIE binary from new entry
    2. Modify offsets to all encryption/decryption code after header has been appended
    3. Encrypt entire binary between elf header and new section (?)
15. ~~Add linked sections to the section themselves~~
    1. ~~Modify hash lookups to only take a symbol name as the parameter~~
16. Modify setters for section/segment subclasses and properties to update whenever changes are made, eg. if the symbol
    for a relocation changes, then the offsets, indexes and info may need to be modified.
17. ~~Rather than having static values for all the properties, look into having an overlay on top of the raw data, so
    that whenever any values are modified or viewed they're on the top of "live" data.~~
    1. Find a way to optimize this - it runs quite slowly when using a bytearray. A couple options would be to either
    use a dirty bit to check if the data has changed, or look into working over a stream rather than bytearray.
    2. Check which properties are affected when changing a related property, and try have the change occur automatically
    3. ~~Extract the get/set_value methods and various properties into a base class~~
    4. Move any data modification to helper file (makes implementing BytesIO easier if necessary)