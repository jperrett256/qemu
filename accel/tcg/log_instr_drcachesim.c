#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/memop.h"
#include "disas/disas.h"

#include "exec/exec-all.h"

static FILE * output_trace_file; // TODO open with zlib and write to it
static FILE * output_dbg_file;

void qemu_log_instr_drcachesim_conf_tracefile(const char * name)
{
    output_trace_file = fopen(name, "wb");
}

void qemu_log_instr_drcachesim_conf_dbgfile(const char * name)
{
    output_dbg_file = fopen(name, "w");
}

void init_drcachesim_backend(CPUArchState * env)
{
    assert(env_cpu(env)->nr_cores == 1 && env_cpu(env)->nr_threads == 1);

    if (output_trace_file == NULL)
        output_trace_file = fopen("output_trace.gz", "wb");
    if (output_dbg_file == NULL)
        output_dbg_file = fopen("output_dbg.txt", "w");

    // TODO could switch to w+b file mode, but then should have a header in trace to separate runs?
}

void emit_drcachesim_entry(CPUArchState * env, cpu_log_entry_t * entry)
{
    assert(output_trace_file);
    assert(output_dbg_file);

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA)
    {
        target_ulong pc = entry->pc;

        MemTxAttrs instr_attrs;
        hwaddr instr_paddr = cpu_get_phys_page_attrs_debug(env_cpu(env), pc & TARGET_PAGE_MASK, &instr_attrs);
        if (instr_paddr != -1) instr_paddr += pc & ~TARGET_PAGE_MASK;

        fprintf(output_dbg_file, "Instruction [ pc: " TARGET_FMT_lx ", paddr: %" HWADDR_PRIx ", opcode: ", pc, instr_paddr);
        for (int64_t i = 0; i < entry->insn_size; i++)
        {
            fprintf(output_dbg_file, "%02hhx", (uint8_t) entry->insn_bytes[i]);
        }
        fprintf(output_dbg_file, " ]\n");

        if (entry->flags & LI_FLAG_MODE_SWITCH) fprintf(output_dbg_file, "CPU MODE SWITCH\n");
        if (entry->flags & LI_FLAG_INTR_MASK) fprintf(output_dbg_file, "EXCEPTION\n");

        for (int64_t i = 0; i < entry->mem->len; i++)
        {
            log_meminfo_t * minfo = &g_array_index(entry->mem, log_meminfo_t, i);

            const char * op_type_str = NULL;
            switch (minfo->flags) {
                case LMI_LD:
                    op_type_str = "LOAD";
                    break;
                case LMI_LD | LMI_CAP:
                    op_type_str = "CLOAD";
                    break;
                case LMI_ST:
                    op_type_str = "STORE";
                    break;
                case LMI_ST | LMI_CAP:
                    op_type_str = "CSTORE";
                    break;
                default:
                    assert(false && "Invalid meminfo flag");
            }
            assert(op_type_str != NULL);

            uint32_t size = memop_size(minfo->op);
            target_ulong vaddr = minfo->addr;

            MemTxAttrs attrs;
            hwaddr paddr = cpu_get_phys_page_attrs_debug(env_cpu(env), vaddr & TARGET_PAGE_MASK, &attrs);
            if (paddr != -1) paddr += vaddr & ~TARGET_PAGE_MASK;

            fprintf(output_dbg_file,
                "Memory Access [ type: %s, size: %u, vaddr: " TARGET_FMT_lx ", paddr: %" HWADDR_PRIx " ]\n",
                op_type_str, size, vaddr, paddr);
        }
    }
}
