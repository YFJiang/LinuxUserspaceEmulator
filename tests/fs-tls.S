.global _start

.section .text
_start:
    mov $158, %rax
    mov $0x1002, %rdi
    lea tls_block(%rip), %rsi
    syscall
    test %rax, %rax
    jne fail

    mov %fs:0, %rax
    cmp $0x12345678, %rax
    jne fail

    mov $1, %rax
    mov $1, %rdi
    lea ok_message(%rip), %rsi
    mov $ok_message_end-ok_message, %rdx
    syscall

    mov $60, %rax
    xor %rdi, %rdi
    syscall

fail:
    mov $60, %rax
    mov $1, %rdi
    syscall

.section .data
.align 8
tls_block:
    .quad 0x12345678

.section .rodata
ok_message:
    .ascii "fs ok\n"
ok_message_end:
