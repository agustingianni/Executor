/*
 * Hooks.cpp
 *
 *  Created on: Jul 3, 2013
 *      Author: anon
 */

#include <iostream>
#include <cstdint>

using namespace std;

#ifdef __arm__
struct __attribute__ ((__packed__)) Context {
        uintptr_t r0;
        uintptr_t r1;
        uintptr_t r2;
        uintptr_t r3;
        uintptr_t r4;
        uintptr_t r5;
        uintptr_t r6;
        uintptr_t r7;
        uintptr_t r8;
        uintptr_t r9;
        uintptr_t r10;
        uintptr_t r11;
        uintptr_t r12;
        uintptr_t r14;
        uintptr_t r13;
};
#elif __x86_64__
struct __attribute__ ((__packed__)) Context {
        uintptr_t rflags;
        uintptr_t r15;
        uintptr_t r14;
        uintptr_t r13;
        uintptr_t r12;
        uintptr_t r11;
        uintptr_t r10;
        uintptr_t r9;
        uintptr_t r8;
        uintptr_t rbp;
        uintptr_t rdi;
        uintptr_t rsi;
        uintptr_t rdx;
        uintptr_t rcx;
        uintptr_t rbx;
        uintptr_t rax;
        uintptr_t rsp;
};
#endif

extern "C" {
    void test_hook(const struct Context *context) {
        // Per thread static variable that handles reentrancy.
        static __thread bool lock(false);

        // If we are already inside the hook due to recursion.
        if (lock) {
            cout << "Avoided recursion" << endl;
            return;
        }

        lock = true;

        cout << "Hooked hookme() (context = " << context << ")" << endl;

#ifdef __arm__
        printf("r0  = %.8x r1  = %.8x r2  = %.8x r3  = %.8x r4  = %.8x\n",
                context->r0, context->r1, context->r2, context->r3, context->r4);

        printf("r5  = %.8x r6  = %.8x r7  = %.8x r8  = %.8x r9  = %.8x\n",
                context->r5, context->r6, context->r7, context->r8, context->r9);

        printf("r10 = %.8x r11 = %.8x r12 = %.8x r13 = %.8x r14 = %.8x\n",
                context->r10, context->r11, context->r12, context->r13, context->r14);


#else
        printf("rax = %.16lx rbx = %.16lx rcx = %.16lx rdx = %.16lx rsi = %.16lx rdi = %.16lx\n",
                context->rax, context->rbx, context->rcx, context->rdx, context->rsi, context->rdi);

        printf("rsp = %.16lx rbp = %.16lx r8  = %.16lx r9  = %.16lx r10 = %.16lx\n", context->rsp,
                context->rbp, context->r8, context->r9, context->r10);

        printf("r11 = %.16lx r12 = %.16lx r13 = %.16lx r14 = %.16lx r15 = %.16lx\n", context->r11,
                context->r12, context->r13, context->r14, context->r15);

 #endif
        lock = false;
    }
}
