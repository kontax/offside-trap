[bits 64]
[org #FUNC_START#]                      ; The offset of the function within the binary

%define text_start  #TEXT_START#        ; Address of text section
%define text_len    #TEXT_LEN#          ; Length of text section
%define oep         #OEP#               ; Original entry point
%define bc          23                  ; Bytecount of overwritten bytes at start of function

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
    ; Save state
    ; rax is pushed before the function call
    push rbx
    push rcx
    push rdi
    push rsi

    ; Get references of function from table
    lea rbx, [table]
    and rax, 0xff
    ; offset * (bytes for each entry) + address of table + offset within entry
    mov rbx, rax                        ; Offset within table
    imul rbx, 0x30                      ; Size of each entry in table
    mov rdi, [rbx+table+0x28]           ; Original entry point of function
    mov rsi, rdi                        ; Store reference to address
    mov rcx, [rbx+table+0x20]           ; Length of function
    push rdi                            ; Save address
    push rax                            ; Save offset

    ; Decrypt the data a byte at a time
    cld                                 ; Set direction flag to increment RDI
    .decrypt:
        lodsb                           ; Load a byte into AX from address in RDI and increment
        xor al, 0xa5                    ; XOR it with the key
        stosb                           ; Store the byte back in the address in RSI and increment
        loop .decrypt                   ; Loop and decrement RCX until 0

    ; Restore the original function bytes
    pop rax                             ; Offset of function
    pop rdi                             ; Original function
    mov rcx, bc                         ; Bytes to restore
    lea rsi, [rbx+table]                ; Original bytes from function

    .restore:
        lodsb                           ; Load byte from table
        stosb                           ; Store byte into original function
        loop .restore                   ; Decrement rcx for length of function

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
    mov rax, [rsp+0x10]                 ; Offset of function in table

    ; offset * (bytes for each entry) + address of table + offset within entry
    mov rbx, rax                        ; Offset within table
    imul rbx, 48                        ; Size of each entry in table
    mov rdi, [rbx+table+0x28]           ; Original entry point of function
    mov rsi, rdi                        ; Store reference to address
    mov rcx, [rbx+table+0x20]           ; Length of function

    cld                                 ; Set the direction flag to increment RDI
    .encrypt:
        lodsb                           ; Load a byte into AX
        xor al, 0xa5                    ; XOR it with the key
        stosb                           ; Store the byte back in the address
        loop encrypt                    ; Loop and decrement RCX until 0

    ; TODO: Overwrite the first few bytes with a call to the decryption routine

    ; Reinstate the state of the program
    pop rsi
    pop rdi
    pop rcx
    pop rbx
    pop rax

    ; Jump to the caller of the function just encrypted
    ret

table: db #TABLE#

                                        ; Address of table containing info on encrypted functions
                                        ; This table has the format;
                                        ;   First 8 bytes in memory of original function (for now)
                                        ;   Next 8 bytes of original function
                                        ;   Next 7 bytes of original function + 1 byte of padding
                                        ;   Next 8 bytes padding
                                        ;   Function length in bytes (little endian)
                                        ;   Address of function in memory (little endian)
                                        ; For example:
                                        ; 89 7d fc 89 75 f8 8b 55
                                        ; fc 8b 45 f8 01 00 00 00
                                        ; 28 03 00 00 00 00 00 00
                                        ; 3f 11 40 00 00 00 00 00
                                        ; Once ELF has been sorted, the first few bytes should disappear
                                        ; May also remove the address of the function as this can be stored when
                                        ; the function is called originally
