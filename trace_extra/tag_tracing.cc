#include "trace_extra/tag_tracing.h"
#include "trace_extra/memory_interceptor.hh"
#include <stdbool.h>
#include "qemu/compiler.h"

EXTERN_C

FILE * tag_tracing_dbg_logfile;

static bool dbg_have_cap_read = false; // DEBUG
static bool dbg_have_cap_write = false; // DEBUG

// doing things like this to make sure that instructions come before corresponding memory accesses in all circumstances
static uint8_t cap_write_tag_value;
static uintptr_t cap_access_vaddr;
static uintptr_t cap_access_haddr;

static void tag_tracing_log_error(const char * error_string)
{
    fprintf(tag_tracing_dbg_logfile, "ERROR: %s\n", error_string);
}

void tag_tracing_cap_read(uintptr_t vaddr, uintptr_t haddr)
{
    if (unlikely(dbg_have_cap_write || dbg_have_cap_read))
    {
        tag_tracing_log_error("Storing cap read data when unconsumed cap access data exists.");
    }

    cap_access_vaddr = vaddr;
    cap_access_haddr = haddr;

    dbg_have_cap_read = true;
}

void tag_tracing_cap_write(uint8_t tag_value, uintptr_t vaddr, uintptr_t haddr)
{
    if (unlikely(dbg_have_cap_write || dbg_have_cap_read))
    {
        tag_tracing_log_error("Storing cap write data when unconsumed cap access data exists.");
    }

    cap_write_tag_value = tag_value;
    cap_access_vaddr = vaddr;
    cap_access_haddr = haddr;

    dbg_have_cap_write = true;
}

void tag_tracing_emit_entry(uint8_t type, uint16_t size, uintptr_t vaddr)
{
    tag_tracing_entry_t trace_entry = {0};
    trace_entry.type = type;
    trace_entry.size = size; // TODO necessary?
    trace_entry.vaddr = vaddr;

    if (type == TAG_TRACING_TYPE_CLOAD)
    {
        if (unlikely(!dbg_have_cap_read))
        {
            tag_tracing_log_error("Missing cap read info for CLOAD.");
            return;
        }

        if (unlikely(vaddr != cap_access_vaddr))
        {
            tag_tracing_log_error("Cap access info does not match expected for CLOAD.");
            fprintf(tag_tracing_dbg_logfile, "expected vaddr: " TARGET_FMT_lx ", vaddr: " TARGET_FMT_lx "\n");
            return;
        }

        trace_entry.haddr = cap_access_haddr;

        dbg_have_cap_read = false;
    }
    else if (type == TAG_TRACING_TYPE_STORE || type == TAG_TRACING_TYPE_CSTORE)
    {
        if (unlikely(!dbg_have_cap_write))
        {
            tag_tracing_log_error("Missing cap write info for STORE/CSTORE.");
            return;
        }

        if (unlikely(vaddr != cap_access_vaddr))
        {
            tag_tracing_log_error("Cap access info does not match expected for STORE/CSTORE.");
            fprintf(tag_tracing_dbg_logfile, "expected vaddr: " TARGET_FMT_lx ", vaddr: " TARGET_FMT_lx "\n");
            return;
        }

        trace_entry.tag_value = cap_write_tag_value;
        trace_entry.haddr = cap_access_haddr;

        dbg_have_cap_write = false;
    }
    else if (unlikely(type == TAG_TRACING_TYPE_LOAD && (dbg_have_cap_write || dbg_have_cap_read)))
    {
        tag_tracing_log_error("Found cap access info for LOAD.");
        return;
    }

    DynamorioTraceInterceptor::mem_logfile.write((char *) &trace_entry, sizeof(tag_tracing_entry_t));
}

EXTERN_C_END
