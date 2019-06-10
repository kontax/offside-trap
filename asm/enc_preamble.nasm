[bits 64]

push #FUNCTION#     ; Return address (current function)
push #OFFSET#       ; Offset in table (for enc func)
push #ENC_FUNC#     ; Encryption address
push rax            ; Save state
mov ax, #OFFSET#    ; Offset in table
push #DEC_FUNC#     ; Address of decryption function
ret
