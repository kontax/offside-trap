[bits 64]

push QWORD #OFFSET#       ; Offset in table (for enc func)
push #DEC_FUNC#     ; Address of decryption function
ret
