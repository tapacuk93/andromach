// Startup for guest test programs: what bionic's crtbegin_dynamic.o does, without the NDK.
    .text
    .globl _start
_start:
    mov x0, sp
    mov x1, xzr
    adrp x2, main
    add x2, x2, :lo12:main
    adrp x3, structors
    add x3, x3, :lo12:structors
    b __libc_init
    .data
    .balign 8
structors: .quad 0,0,0,0,0,0
    .section .note.GNU-stack,"",%progbits
    .section .note.android.ident,"a",%note
    .balign 4
    .long 2f-1f, 3f-2f, 1
1:  .asciz "Android"
2:  .long 35
3:
