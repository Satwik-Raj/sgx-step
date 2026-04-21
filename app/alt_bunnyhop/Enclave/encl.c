#include "encl_t.h"
#include <stdint.h>
#define nops_20 asm volatile("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop");
/* runs only when bit = 1 */
//noinline forces compiler to keep it as a separate function, no inline optimisation, so that call is clearly visible
//. aligned make it on the start of a page like address 3000
int __attribute__((noinline, aligned(4096))) secret_function(void) {
    nops_20
    volatile int x = 0;
    volatile int y = 0;
    x += y;
    y *= 2;
    x = y*3 + 2;
    return x;
}
int __attribute__((noinline, aligned(4096))) all_function(void) {
    nops_20
    volatile int x = 0;
    volatile int y = 0;
    x += y;
    y *= 2;
    x = y*3 + 2;
    return y;
}
void __attribute__((noinline, aligned(4096))) ecall_process_bits(uint8_t *bits, size_t len) {
    nops_20
    for (size_t i = 0; i < len; i++) {
        volatile int dummy = 1;
        all_function();//called everytime irrespective of bit being 1 or 0
        if (bits[i]) {
            secret_function();//only called when bit is 1
        }
    }
    
}
