[bits 64]

push r15
sub rsp, 8

call reloc_base
reloc_base:
    pop r15
    sub r15, 11

jmp main

main:
        push rbp
        mov rbp, rsp

        sub rsp, 96                         ; shadow space max 12 params
        
        mov rcx, [r15 + data + 16]
        call [r15 + data]                   ; func
        mov [r15 + data + 8], rax           ; funcRetVal

        mov rcx, r15
        add rcx, data + 128
        xor rdx, rdx
        call [r15 + data + 112]             ; NtContinue
        
align 16
data:
; .func1: dq 0                      0
; .retVal: dq 0                     8
; .params: db 0 dup (96)            16      max 12
; .ntContinue: dq 0                 112
; .ntContinueCtx: db 0 dup (1232)   128 <- after align16
; .stringArgData:                   1360
