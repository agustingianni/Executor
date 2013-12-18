# Long jump to the next dword
ldr pc, [pc, #-4]
.long 0x41424344

# Va pusheando en orden ascenciente.
push {r13}
push {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r14}
mov r0, sp
ldr  r8, [pc, #12]
blx r8
pop {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r14}
ldr sp, [sp]
add pc, pc, #4
.long 0x41424344


