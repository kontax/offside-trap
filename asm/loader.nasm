[bits 64]
[default rel]

%define text_start  #TEXT_START#        ; Address of text section
%define text_len    #TEXT_LEN#          ; Length of text section
%define oep         #OEP#               ; Original entry point
%define bc          11                  ; Bytecount of overwritten bytes at start of function
%define length      16                  ; Entry point in table of the  total length of the function being decrypted
%define ret_func    24                  ; Entry point in table of the adderss of the function being decrypted
%define tbl_sz      32                  ; Full size of each entry within the table in bytes

entry:
    ; Save the state of the program
    push rax
    push rdi
    push rsi
    push rdx
    push rcx

    ; Call mprotect to make the text segment writable
    mov rdi, text_start                 ; Start address
    mov rsi, text_len                   ; Length of data
    mov rdx, 7                          ; RWX
    mov rax, 10                         ; mprotect syscall
    syscall

    ; Go to original entry point
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    push oep
    ret


decrypt:
    ; ROP dummy stack entries
    push 0x0fffffff                     ; Address of encryption function
    push 0x0fffffff                     ; Address of function being decrypted to return to
    nop

    ; Save state
    push rax
    push rbx
    push rcx
    push rdi
    push rsi

    ; Get references of function from table
    lea rbx, [table]                    ; Store relative address of table
    mov rax, [rsp+0x38]                 ; Offset within table - from preamble stack push
    imul rax, tbl_sz                    ; Size of each entry in table

    ; offset * (bytes for each entry) + address of table + offset within entry
    add rbx, rax                        ; Offset within table
    mov rdi, [rbx+ret_func]             ; Original entry point of function
    mov rsi, rdi                        ; Store reference to address
    mov rcx, [rbx+length]               ; Length of function
    push rdi                            ; Save address

    ; Decrypt the data a byte at a time
    cld                                 ; Set direction flag to increment RDI
    .decrypt:
        lodsb                           ; Load a byte into AX from address in RDI and increment
        xor al, 0xa5                    ; XOR it with the key
        stosb                           ; Store the byte back in the address in RSI and increment
        loop .decrypt                   ; Loop and decrement RCX until 0

    ; Restore the original function bytes
    pop rdi                             ; Original function
    mov rcx, bc                         ; Bytes to restore
    lea rsi, [rbx]                      ; Original bytes from function

    .restore:
        lodsb                           ; Load byte from table
        stosb                           ; Store byte into original function
        loop .restore                   ; Decrement rcx for length of function

    ; Set up stack for ROP
    lea rax, [encrypt]
    mov QWORD [rsp+0x30], rax           ; Encryption function address
    mov rdi, [rbx+ret_func]
    mov [rsp+0x28], rdi                 ; Return address function

    ; Restore state and return to function
    pop rsi
    pop rdi
    pop rcx
    pop rbx
    pop rax
    ret                                 ; Original function is stored on stack


encrypt:
    ; Encrypt a function one byte at a time

    ; Save state
    push rax
    push rbx
    push rcx
    push rdi
    push rsi

    ; Get references of function from table
    lea rbx, [table]                    ; Store relative address of table
    mov rax, [rsp+0x28]                 ; Offset of function in table
    imul rax, tbl_sz                    ; Size of each entry in table

    ; offset * (bytes for each entry) + address of table + offset within entry
    add rbx, rax                        ; Offset within table
    mov rdi, [rbx+ret_func]             ; Original entry point of function
    mov rsi, rdi                        ; Store reference to address
    mov rcx, [rbx+length]               ; Length of function

    cld                                 ; Set the direction flag to increment RDI
    .encrypt:
        lodsb                           ; Load a byte into AX
        xor al, 0xa5                    ; XOR it with the key
        stosb                           ; Store the byte back in the address
        loop .encrypt                   ; Loop and decrement RCX until 0

    ; Overwrite the first few bytes with the decryption preamble
    mov rdi, [rbx+ret_func]             ; Original entry point of function
    lea rsi, [preamble]                 ; Get preamble bytes
    mov rcx, bc                         ; Bytes to restore

    cld
    .preamble:
        lodsb                           ; Load byte from table
        stosb                           ; Store byte into original function
        loop .preamble                  ; Decrement rcx for length of function

    ; Replace offset and address within preamble
    mov rax, [rsp+0x28]                 ; Offset of function in table
    mov rbx, [rbx+ret_func]             ; Original entry point of function
    mov [rbx+0x1], al                   ; Replace offset in preamble

    ; Reinstate the state of the program
    pop rsi
    pop rdi
    pop rcx
    pop rbx
    pop rax
    add rsp, 8                          ; Remove offset from stack

    ; Jump to the caller of the function just encrypted
    ret

table: db #TABLE#

                                        ; Address of table containing info on encrypted functions
                                        ; This table has the format;
                                        ;   First 11 bytes in memory of original function (for now)
                                        ;   5 bytes of padding
                                        ;   Function length in bytes (little endian)
                                        ;   Address of function in memory (little endian)
                                        ; For example:
                                        ; 89 7d fc 89 75 f8 8b 55
                                        ; 28 03 11 00 00 00 00 00
                                        ; 3f 11 40 00 00 00 00 00
                                        ; Once ELF has been sorted, the first few bytes should disappear
                                        ; May also remove the address of the function as this can be stored when
                                        ; the function is called originally

preamble: db #PREAMBLE#
                                        ; This is the bytecode of a generic preamble, used to re-encrypt the
                                        ; function on exit. The bytes that are distinct to each function (ie.
                                        ; OFFSET and FUNCTION) have been set randomly for each bit. These are
                                        ; subsequently replaced in the encryption function.
