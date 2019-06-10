[bits 64]

push #OFFSET#       ; Offset in table (for enc func)
push #ENC_FUNC#     ; Encryption address
push #FUNCTION#     ; Return address (current function)
push rax            ; Save state
mov ax, #OFFSET#    ; Offset in table
push #DEC_FUNC#     ; Address of decryption function
ret
