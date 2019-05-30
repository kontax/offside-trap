[bits 64]
[org 0x4a0584]

; Save the state of the program
push rax
push rdi
push rsi
push rdx
push rcx

; Call mprotect to make the text segment writable
mov rdi, 0x400000   ; Start address
mov rsi, 0xa1000    ; Length of data
mov rdx, 7          ; RWX
mov rax, 10         ; mprotect syscall
syscall

; Details of the original text data
mov rdi, 0x4003b0   ; Start address
mov rsi, rdi        ;
mov rcx, 0xa01d4    ; Length for loop

; Decrypt the data a byte at a time
cld                 ; Set direction flag to increment RDI
decrypt:
	lodsb           ; Load a byte into AX
	xor al, 0xa5    ; XOR it with the key
	stosb           ; Store the byte back in the address
	loop decrypt    ; Loop and decrement RCX until 0

; Reinstate the state of the program
pop rcx
pop rdx
pop rsi
pop rdi
pop rax

; Jump to the OEP
push 0x4009D0
ret
