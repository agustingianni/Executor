; anon@research:~$ yasm --arch=x86 --machine=amd64 example.s -o example -f elf
bits 64

; Build the jmp to trampoline for x64.
jmp [rip+0]
dq 0xcccccccccccccccc

add rsp, 8

; Trampoline code:
; Save GPR
push rsp
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15

; Save RFLAGS
pushfq

; Build a reference to our Context *
mov rdi, rsp

; Call the hook function
call [rip+2]

; Jump over the hook function address.
jmp restore

; Hook function address
dq 0xcccccccccccccccc

; Restore RFLAGS
restore:
popfq

; Restore GPR
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax
pop rsp

; Call the original function
call [rip+0]

; Original function address + ammount of bytes overwritten by the trampoline.
dq 0xcccccccccccccccc


