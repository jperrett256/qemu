#include "trace_extra/tag_tracing.h"
#include "trace_extra/memory_interceptor.hh"
#include <stdbool.h>
#include "qemu/compiler.h"

EXTERN_C

FILE * tag_tracing_dbg_logfile;

static bool dbg_have_cap_read = false; // DEBUG
static bool dbg_have_cap_write = false; // DEBUG

static uint64_t dbg_entries_dropped = 0;
static uint64_t dbg_entries_total = 0;

// doing things like this to make sure that instructions come before corresponding memory accesses in all circumstances
static uint8_t cap_write_tag_value;
static uintptr_t cap_access_vaddr;
static uintptr_t cap_access_haddr;

static void tag_tracing_log_error(const char * error_string)
{
#ifdef TAG_TRACING_DBG_LOG
    fprintf(tag_tracing_dbg_logfile, "ERROR: %s\n", error_string);
#endif
}

static void tag_tracing_log_warning(const char * error_string)
{
#ifdef TAG_TRACING_DBG_LOG
    fprintf(tag_tracing_dbg_logfile, "WARNING: %s\n", error_string);
#endif
}

static void tag_tracing_print_statistics(void)
{
    // NOTE printing these regardless of whether text logging is enabled
    fprintf(tag_tracing_dbg_logfile,
        "Statistics: dropped %lu/%lu entries.\n", dbg_entries_dropped, dbg_entries_total);
}

void tag_tracing_init(const char * text_log_filename)
{
    tag_tracing_dbg_logfile = fopen(text_log_filename, "wb");
}

void tag_tracing_quit(void)
{
    tag_tracing_print_statistics();
    fclose(tag_tracing_dbg_logfile);
}

void tag_tracing_end_instr(void)
{
    if (unlikely(dbg_have_cap_write || dbg_have_cap_read))
    {
        if (dbg_have_cap_write) tag_tracing_log_error("Unconsumed cap write in last instruction.");
        if (dbg_have_cap_read) tag_tracing_log_error("Unconsumed cap read in last instruction.");
    }

    dbg_have_cap_read = false;
    dbg_have_cap_write = false;
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
    dbg_entries_total++;

    tag_tracing_entry_t trace_entry = {0};
    trace_entry.type = type;
    trace_entry.size = size; // TODO necessary?
    trace_entry.vaddr = vaddr;

    if (type == TAG_TRACING_TYPE_CLOAD)
    {
        if (unlikely(!dbg_have_cap_read))
        {
            tag_tracing_log_error("Missing cap read info for CLOAD.");

            // NOTE including in trace anyway
        }
        else
        {
            if (unlikely(vaddr != cap_access_vaddr))
            {
                tag_tracing_log_error("Cap access info does not match expected for CLOAD.");
                fprintf(tag_tracing_dbg_logfile, "expected vaddr: " TARGET_FMT_lx ", vaddr: " TARGET_FMT_lx "\n",
                    cap_access_vaddr, vaddr);

                dbg_entries_dropped++;
                return;
            }

            trace_entry.haddr = cap_access_haddr;
        }

        dbg_have_cap_read = false;
    }
    else if (type == TAG_TRACING_TYPE_STORE || type == TAG_TRACING_TYPE_CSTORE)
    {
        if (unlikely(!dbg_have_cap_write))
        {
            tag_tracing_log_warning("Missing cap write info for STORE/CSTORE.");

            // NOTE can safely include in trace if non-capability write as we know it clears the tag
            if (type == TAG_TRACING_TYPE_STORE) // equivalently: if (size < 16)
            {
                trace_entry.tag_value = 0;
            }
            else
            {
                tag_tracing_log_error("Dropping CSTORE from trace because tag value unknown.");

                dbg_entries_dropped++;
                return; // NOTE no good way to handle capability writes without tag info!
            }
        }
        else
        {
            if (unlikely(vaddr != cap_access_vaddr))
            {
                tag_tracing_log_error("Cap access info does not match expected for STORE/CSTORE.");
                fprintf(tag_tracing_dbg_logfile, "expected vaddr: " TARGET_FMT_lx ", vaddr: " TARGET_FMT_lx "\n",
                    cap_access_vaddr, vaddr);

                dbg_entries_dropped++;
                return;
            }

            trace_entry.tag_value = cap_write_tag_value;
            trace_entry.haddr = cap_access_haddr;
            dbg_have_cap_write = false;
        }

    }
    else if (unlikely(type == TAG_TRACING_TYPE_LOAD && (dbg_have_cap_write || dbg_have_cap_read)))
    {
        tag_tracing_log_warning("Found cap access info for instruction with LOAD.");

        // NOTE this only appears to happen for atomic instructions, which both read and write
        // TODO could add hardware address in there if we wanted
    }

    DynamorioTraceInterceptor::mem_logfile.write((char *) &trace_entry, sizeof(tag_tracing_entry_t));
}

EXTERN_C_END
