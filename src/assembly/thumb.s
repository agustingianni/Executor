.syntax unified

self: 
b.w self
nop

# Long jump to the next dword
ldr pc, [pc, #0]
.long 0x41424344

# Emulate a push sp
str sp, [sp, #-4]!
#sub sp, sp, #4
push {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r14}
mov.w r0, sp
ldr  r8, [pc, #12]
blx r8
pop {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r14}
ldr sp, [sp]
b past
.long 0x41424344
past:
.long 0x90909090
