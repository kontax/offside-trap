[bits 64]

push 0x2        ; Offset in table (for enc func)    ; 0x6a 0x02
push 0x40113f   ; Address of decryption function    ; 0x68 0x3f 0x11 0x40 0x00
ret                                                 ; 0xc3
