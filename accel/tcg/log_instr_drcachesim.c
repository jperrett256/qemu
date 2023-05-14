#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>
#include <zlib.h>

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/memop.h"
#include "disas/disas.h"

#include "exec/exec-all.h"

#define FMT_ADDR "%016" PRIx64

// TODO create user-set flag instead?
// #define TAG_TRACING_DBG_LOG


static gzFile output_trace_file;
static FILE * output_dbg_file;


typedef struct stats_t stats_t;
struct stats_t
{
    uint64_t num_entries_total;

    uint64_t num_instructions;
    uint64_t num_LOADs;
    uint64_t num_STOREs;
    uint64_t num_CLOADs;
    uint64_t num_CSTOREs;

    uint64_t num_instructions_missing_paddr;
    uint64_t num_LOADs_missing_paddr;
    uint64_t num_STOREs_missing_paddr;
    uint64_t num_CLOADs_missing_paddr;
    uint64_t num_CSTOREs_missing_paddr;

    uint64_t num_exceptions_also_mode_switches;
    uint64_t num_instructions_missing_paddr_also_exceptions;

    uint64_t num_exceptions;
    uint64_t num_mode_switches;
    uint64_t num_atomic_ops;
    uint64_t num_paddrs_equal_vaddrs;
    uint64_t num_entries_missing_paddr;
    uint64_t num_entries_invalid_paddr;
    uint64_t num_impossible_errors;
};

static stats_t dbg_stats = {0};

static void tag_tracing_print_statistics(FILE * output_file)
{
    fprintf(output_file, "Statistics:\n");
    fprintf(output_file, "\tTotal: %lu\n", dbg_stats.num_entries_total);
    fprintf(output_file, "\n");
    fprintf(output_file, "\tInstructions: %lu\n", dbg_stats.num_instructions);
    fprintf(output_file, "\tLOADs: %lu\n", dbg_stats.num_LOADs);
    fprintf(output_file, "\tSTOREs: %lu\n", dbg_stats.num_STOREs);
    fprintf(output_file, "\tCLOADs: %lu\n", dbg_stats.num_CLOADs);
    fprintf(output_file, "\tCSTOREs: %lu\n", dbg_stats.num_CSTOREs);
    fprintf(output_file, "\n");
    fprintf(output_file, "\tInstructions without paddr: %lu\n", dbg_stats.num_instructions_missing_paddr);
    fprintf(output_file, "\tLOADs without paddr: %lu\n", dbg_stats.num_LOADs_missing_paddr);
    fprintf(output_file, "\tSTOREs without paddr: %lu\n", dbg_stats.num_STOREs_missing_paddr);
    fprintf(output_file, "\tCLOADs without paddr: %lu\n", dbg_stats.num_CLOADs_missing_paddr);
    fprintf(output_file, "\tCSTOREs without paddr: %lu\n", dbg_stats.num_CSTOREs_missing_paddr);
    fprintf(output_file, "\n");
    fprintf(output_file, "\tExceptions that are also mode switches: %lu\n", dbg_stats.num_exceptions_also_mode_switches);
    fprintf(output_file, "\tInstructions without paddr that are also exceptions: %lu\n", dbg_stats.num_instructions_missing_paddr_also_exceptions);
    fprintf(output_file, "\n");
    fprintf(output_file, "\tExceptions (synchronous/asynchronous): %lu\n", dbg_stats.num_exceptions);
    fprintf(output_file, "\tCPU mode switches: %lu\n", dbg_stats.num_mode_switches);
    fprintf(output_file, "\tAtomic operations: %lu\n", dbg_stats.num_atomic_ops);
    fprintf(output_file, "\tCases where paddr == vaddr: %lu\n", dbg_stats.num_paddrs_equal_vaddrs);
    fprintf(output_file, "\tCases where paddr missing: %lu\n", dbg_stats.num_entries_missing_paddr);
    fprintf(output_file, "\tCases where paddr invalid (includes missing): %lu\n", dbg_stats.num_entries_invalid_paddr);
    fprintf(output_file, "\tImpossible errors (supposedly): %lu\n", dbg_stats.num_impossible_errors);
}


enum custom_trace_type_t
{
    CUSTOM_TRACE_TYPE_INSTR,
    CUSTOM_TRACE_TYPE_LOAD,
    CUSTOM_TRACE_TYPE_STORE,
    CUSTOM_TRACE_TYPE_CLOAD,
    CUSTOM_TRACE_TYPE_CSTORE,
};

typedef struct custom_trace_entry_t custom_trace_entry_t;
struct custom_trace_entry_t
{
    uint8_t type;
    uint8_t tag; // ignore for LOADs
    uint16_t size;
    uintptr_t vaddr; // only for reconstructing the minority of missing paddrs
    uintptr_t paddr;
};


static void cleanup_drcachesim_backend(void)
{
    if (output_trace_file)
        gzclose(output_trace_file);
    if (output_dbg_file)
    {
        tag_tracing_print_statistics(output_dbg_file);
        fclose(output_dbg_file);
    }
}

void qemu_log_instr_drcachesim_conf_tracefile(const char * name)
{
    output_trace_file = gzopen(name, "wb");
}

void qemu_log_instr_drcachesim_conf_dbgfile(const char * name)
{
    output_dbg_file = fopen(name, "w");
}

void init_drcachesim_backend(CPUArchState * env)
{
    assert(env_cpu(env)->nr_cores == 1 && env_cpu(env)->nr_threads == 1);

    if (output_trace_file == NULL)
        output_trace_file = gzopen("output_trace.gz", "wb");
    if (output_dbg_file == NULL)
        output_dbg_file = fopen("output_dbg.txt", "w");

    // TODO could switch to w+b file mode, but then should have a header in trace to separate runs?
    // TODO could have it check we aren't overwriting traces?

    atexit(cleanup_drcachesim_backend);
}


// NOTE can get this information by running dmesg within QEMU
#define MEMORY_SIZE (2 * 1024LL*1024*1024)
#define BASE_PADDR 0x80000000

static bool check_paddr_valid(uint64_t paddr)
{
    return paddr >= BASE_PADDR && paddr < BASE_PADDR + MEMORY_SIZE;
}

static void emit_trace_entry(uint8_t type, uint16_t size, uint64_t vaddr, uint64_t paddr, uint8_t tag)
{
    dbg_stats.num_entries_total++;

    custom_trace_entry_t trace_entry = {0};
    trace_entry.type = type;
    trace_entry.tag = tag;
    trace_entry.size = size;
    trace_entry.vaddr = vaddr;
    trace_entry.paddr = paddr;

    gzwrite(output_trace_file, &trace_entry, sizeof(trace_entry));
}

void emit_drcachesim_entry(CPUArchState * env, cpu_log_entry_t * entry)
{
    assert(output_trace_file);
    assert(output_dbg_file);

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA)
    {
        target_ulong pc = entry->pc;

        uint64_t instr_paddr = entry->paddr;

        if (instr_paddr == -1) dbg_stats.num_entries_missing_paddr++;
        if (!check_paddr_valid(instr_paddr)) dbg_stats.num_entries_invalid_paddr++;
        if (instr_paddr == -1 && !check_paddr_valid(instr_paddr)) dbg_stats.num_impossible_errors++;
        if (instr_paddr == pc) dbg_stats.num_paddrs_equal_vaddrs++;

#ifdef TAG_TRACING_DBG_LOG
        fprintf(output_dbg_file, "Instruction [ pc: " TARGET_FMT_lx ", paddr: " FMT_ADDR ", opcode: ", pc, instr_paddr);
        for (int64_t i = 0; i < entry->insn_size; i++)
        {
            fprintf(output_dbg_file, "%02hhx", (uint8_t) entry->insn_bytes[i]);
        }
        fprintf(output_dbg_file, " ]\n");

        if (entry->flags & LI_FLAG_MODE_SWITCH) fprintf(output_dbg_file, "CPU MODE SWITCH\n");
        if (entry->flags & LI_FLAG_INTR_MASK) fprintf(output_dbg_file, "EXCEPTION\n");
#endif

        if (entry->flags & LI_FLAG_MODE_SWITCH) dbg_stats.num_mode_switches++;
        if (entry->flags & LI_FLAG_INTR_MASK)
        {
            dbg_stats.num_exceptions++;
            if (entry->flags & LI_FLAG_MODE_SWITCH) dbg_stats.num_exceptions_also_mode_switches++;
        }
        dbg_stats.num_instructions++;
        if (!instr_paddr)
        {
            dbg_stats.num_instructions_missing_paddr++;
            if (entry->flags & LI_FLAG_INTR_MASK) dbg_stats.num_instructions_missing_paddr_also_exceptions++;
        }

        emit_trace_entry(CUSTOM_TRACE_TYPE_INSTR, entry->insn_size, pc, instr_paddr, 0);

        if (entry->mem->len == 2) dbg_stats.num_atomic_ops++;
        if (entry->mem->len > 2) dbg_stats.num_impossible_errors++;

        for (int64_t i = 0; i < entry->mem->len; i++)
        {
            log_meminfo_t * minfo = &g_array_index(entry->mem, log_meminfo_t, i);

            uint32_t size = memop_size(minfo->op);
            target_ulong vaddr = minfo->addr;

            uint64_t paddr = minfo->paddr;

            if (paddr == -1) dbg_stats.num_entries_missing_paddr++;
            if (!check_paddr_valid(paddr)) dbg_stats.num_entries_invalid_paddr++;
            if (paddr == -1 && !check_paddr_valid(paddr)) dbg_stats.num_impossible_errors++;
            if (paddr == vaddr) dbg_stats.num_paddrs_equal_vaddrs++;

            uint16_t op_type;
            switch (minfo->flags) {
                case LMI_LD:
                    op_type = CUSTOM_TRACE_TYPE_LOAD;

                    dbg_stats.num_LOADs++;
                    if (paddr == -1) dbg_stats.num_LOADs_missing_paddr++;
                    break;
                case LMI_ST:
                    op_type = CUSTOM_TRACE_TYPE_STORE;

                    dbg_stats.num_STOREs++;
                    if (paddr == -1) dbg_stats.num_STOREs_missing_paddr++;
                    break;
                case LMI_LD | LMI_CAP:
                    op_type = CUSTOM_TRACE_TYPE_CLOAD;

                    dbg_stats.num_CLOADs++;
                    if (paddr == -1) dbg_stats.num_CLOADs_missing_paddr++;
                    break;
                case LMI_ST | LMI_CAP:
                    op_type = CUSTOM_TRACE_TYPE_CSTORE;

                    dbg_stats.num_CSTOREs++;
                    if (paddr == -1) dbg_stats.num_CSTOREs_missing_paddr++;
                    break;
                default:
                    assert(false && "Invalid meminfo flag");
            }

            uint8_t tag = 0;
#ifdef TARGET_CHERI
            if (minfo->flags & LMI_CAP) tag = minfo->cap.cr_tag;
#endif

#ifdef TAG_TRACING_DBG_LOG
            fprintf(output_dbg_file,
                "Memory Access [ type: %s, size: %u, vaddr: " TARGET_FMT_lx ", paddr: " FMT_ADDR,
                op_type == TAG_TRACING_TYPE_LOAD ? "LOAD" :
                op_type == TAG_TRACING_TYPE_STORE ? "STORE" :
                op_type == TAG_TRACING_TYPE_CLOAD ? "CLOAD" :
                op_type == TAG_TRACING_TYPE_CSTORE ? "CSTORE" : "UNKNOWN",
                size, vaddr, paddr);
            if (minfo->flags & LMI_CAP) fprintf(output_dbg_file, ", tag: %d", tag);
            fprintf(output_dbg_file, " ]\n");
#endif

            emit_trace_entry(op_type, size, vaddr, paddr, tag);
        }
    }
}
