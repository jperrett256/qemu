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

// NOTE copied from qemu/softmmu/memory.c
static hwaddr memory_region_to_absolute_addr(MemoryRegion *mr, hwaddr offset)
{
    MemoryRegion *root;
    hwaddr abs_addr = offset;

    abs_addr += mr->addr;
    for (root = mr; root->container; ) {
        root = root->container;
        abs_addr += root->addr;
    }

    return abs_addr;
}

void emit_drcachesim_entry(CPUArchState * env, cpu_log_entry_t * entry)
{
    assert(output_trace_file);
    assert(output_dbg_file);

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA)
    {
        target_ulong pc = entry->pc;

        MemTxAttrs attrs_instr;
        hwaddr instr_haddr = cpu_get_phys_page_attrs_debug(env_cpu(env), pc & TARGET_PAGE_MASK, &attrs_instr);
        if (instr_haddr != -1) instr_haddr += pc & ~TARGET_PAGE_MASK;

        fprintf(output_dbg_file, "Instruction [ pc: " TARGET_FMT_lx ", hwaddr: %" HWADDR_PRIx ", opcode: ", pc, instr_haddr);
        for (int64_t i = 0; i < entry->insn_size; i++)
        {
            fprintf(output_dbg_file, "%02hhx", (uint8_t) entry->insn_bytes[i]);
        }
        fprintf(output_dbg_file, " ]\n");

        // TODO check not exception/trap?

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

            int mmu_idx = cpu_mmu_index(env, false);
            void * host_addr = NULL;

            if (minfo->flags & LMI_LD)
            {
                host_addr = probe_read(env, vaddr, 1, mmu_idx, pc);
            }
            else if (minfo->flags & LMI_ST)
            {
                if (minfo->flags & LMI_CAP)
                {
#ifdef TARGET_CHERI
                    host_addr = probe_cap_write(env, vaddr, 1, mmu_idx, pc);
#endif
                }
                else
                {
                    host_addr = probe_write(env, vaddr, 1, mmu_idx, pc); // TODO sometimes fails and returns NULL?
                }
            }
            else
                assert(false && "Memory access is neither load or store.");

            ram_addr_t paddr = host_addr ? qemu_ram_addr_from_host(host_addr) : 0;

            // TODO is the hwaddr what we actually want (vs ram addr)? why are the values >2GiB (memory of VM)?
            hwaddr mr_haddr = 0;
            hwaddr haddr = 0;
            if (host_addr)
            {
                ram_addr_t offset;
                MemoryRegion * mr = memory_region_from_host(host_addr, &offset);
                haddr = memory_region_to_absolute_addr(mr, offset);
                mr_haddr = mr->addr;
            }

            MemTxAttrs attrs;
            hwaddr haddr2 = cpu_get_phys_page_attrs_debug(env_cpu(env), vaddr & TARGET_PAGE_MASK, &attrs);
            if (haddr2 != -1) haddr2 += vaddr & ~TARGET_PAGE_MASK;

            fprintf(output_dbg_file,
                "Memory Access [ type: %s, size: %u, \n"
                "\tvaddr: " TARGET_FMT_lx ", ram addr: " RAM_ADDR_FMT ", mem region hwaddr: %" HWADDR_PRIx ", hwaddr: %" HWADDR_PRIx ", hwaddr2: %" HWADDR_PRIx " ]\n",
                op_type_str, size, vaddr, paddr, mr_haddr, haddr, haddr2);
        }
    }
}
