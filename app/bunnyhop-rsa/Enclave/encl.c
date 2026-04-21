#include "encl_t.h"
#include <stdint.h>
#define nops_20 asm volatile("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop");
#define memory_barrier asm volatile ("sfence;\nmfence;\nlfence");
/* 4096 bytes ≈ one page */

/* runs only when bit = 1 */
//noinline forces compiler to keep it as a separate function, no inline optimisation, so that call is clearly visible
// aligned make it on the start of a page like address 3000
int __attribute__((noinline, aligned(4096))) secret_function(void) {
    volatile int x = 0;
    memory_barrier
    return x;
}
int __attribute__((noinline, aligned(4096))) all_function(void) {
    volatile int x = 0;
    memory_barrier
    return x;
}

void __attribute__((noinline, aligned(4096))) ecall_process_bits(uint8_t *bits, size_t len) {
    volatile int dummy = 1;
    memory_barrier
    for (size_t i = 0; i < len; i++) {
        all_function(); //called everytime irrespective of bit being 1 or 0
        for(int j=0;j<5000;j++){
                nops_20
            }
        memory_barrier
        if (bits[i]) {
            secret_function();//only called when bit is 1
            memory_barrier
        }
        for(int j=0;j<5000;j++){
                nops_20
            }
        memory_barrier
    }
    for(int j=0;j<5000;j++){
                nops_20
            }
        memory_barrier
    all_function(); 
}
