#include "trace_extra/tag_tracing.h"
#include "trace_extra/memory_interceptor.hh"
#include <stdbool.h>
#include "qemu/compiler.h"

EXTERN_C

FILE * tag_tracing_dbg_logfile;

static bool dbg_have_cap_read = false;
static bool dbg_have_cap_write = false;

typedef struct stats_t stats_t;
struct stats_t
{
    uint64_t num_total;

    uint64_t num_LOADs;
    uint64_t num_STOREs;
    uint64_t num_CLOADs;
    uint64_t num_CSTOREs;

    uint64_t num_STOREs_missing_cap_info;
    uint64_t num_CLOADs_missing_cap_info;
    uint64_t num_CSTOREs_missing_cap_info;

    uint64_t num_impossible_errors;
};

static stats_t dbg_stats = {0};

// NOTE capability information is taken from cheri_tagmem before corresponding instruction is traced
static uint8_t cap_access_tag_value;
static uintptr_t cap_access_vaddr;
static uintptr_t cap_access_paddr;

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
    fprintf(tag_tracing_dbg_logfile, "Statistics:\n");
    fprintf(tag_tracing_dbg_logfile, "\tTotal: %lu\n", dbg_stats.num_total);
    fprintf(tag_tracing_dbg_logfile, "\tLOADs: %lu\n", dbg_stats.num_LOADs);
    fprintf(tag_tracing_dbg_logfile, "\tSTOREs: %lu\n", dbg_stats.num_STOREs);
    fprintf(tag_tracing_dbg_logfile, "\tCLOADs: %lu\n", dbg_stats.num_CLOADs);
    fprintf(tag_tracing_dbg_logfile, "\tCSTOREs: %lu\n", dbg_stats.num_CSTOREs);
    fprintf(tag_tracing_dbg_logfile, "\tSTOREs missing capability information: %lu\n", dbg_stats.num_STOREs_missing_cap_info);
    fprintf(tag_tracing_dbg_logfile, "\tCLOADs missing capability information: %lu\n", dbg_stats.num_CLOADs_missing_cap_info);
    fprintf(tag_tracing_dbg_logfile, "\tCSTOREs missing capability information: %lu\n", dbg_stats.num_CSTOREs_missing_cap_info);
    fprintf(tag_tracing_dbg_logfile, "\tImpossible errors (supposedly): %lu\n", dbg_stats.num_impossible_errors);
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
        if (dbg_have_cap_write)
        {
            dbg_stats.num_impossible_errors++;
            tag_tracing_log_error("Unconsumed cap write in last instruction.");
        }
        if (dbg_have_cap_read)
        {
            dbg_stats.num_impossible_errors++;
            tag_tracing_log_error("Unconsumed cap read in last instruction.");
        }
    }

    dbg_have_cap_read = false;
    dbg_have_cap_write = false;
}

void tag_tracing_cap_read(uint8_t tag_value, uintptr_t vaddr, uintptr_t paddr)
{
    if (unlikely(dbg_have_cap_write || dbg_have_cap_read))
    {
        tag_tracing_log_error("Storing cap read data when unconsumed cap access data exists.");
    }

    cap_access_tag_value = tag_value;
    cap_access_vaddr = vaddr;
    cap_access_paddr = paddr;

    dbg_have_cap_read = true;
}

void tag_tracing_cap_write(uint8_t tag_value, uintptr_t vaddr, uintptr_t paddr)
{
    if (unlikely(dbg_have_cap_write || dbg_have_cap_read))
    {
        tag_tracing_log_error("Storing cap write data when unconsumed cap access data exists.");
    }

    cap_access_tag_value = tag_value;
    cap_access_vaddr = vaddr;
    cap_access_paddr = paddr;

    dbg_have_cap_write = true;
}

void tag_tracing_emit_entry(uint8_t type, uint16_t size, uintptr_t vaddr)
{
    dbg_stats.num_total++;

    tag_tracing_entry_t trace_entry = {0};
    trace_entry.type = type;
    trace_entry.size = size; // TODO necessary?
    trace_entry.vaddr = vaddr;

    if (type == TAG_TRACING_TYPE_CLOAD)
    {
        dbg_stats.num_CLOADs++;

        if (unlikely(!dbg_have_cap_read))
        {
            tag_tracing_log_error("Missing cap read info for CLOAD.");

            trace_entry.tag_value = TAG_TRACING_TAG_UNKNOWN;

            // NOTE including in trace anyway
            dbg_stats.num_CLOADs_missing_cap_info++;
        }
        else
        {
            if (unlikely(vaddr != cap_access_vaddr))
            {
                tag_tracing_log_error("Cap access info does not match expected for CLOAD.");
                fprintf(tag_tracing_dbg_logfile, "expected vaddr: " TARGET_FMT_lx ", vaddr: " TARGET_FMT_lx "\n",
                    cap_access_vaddr, vaddr);

                dbg_stats.num_impossible_errors++;
                return;
            }

            trace_entry.tag_value = cap_access_tag_value;
            trace_entry.paddr = cap_access_paddr;
        }

        dbg_have_cap_read = false;
    }
    else if (type == TAG_TRACING_TYPE_STORE || type == TAG_TRACING_TYPE_CSTORE)
    {
        if (type == TAG_TRACING_TYPE_STORE) dbg_stats.num_STOREs++;
        else                                dbg_stats.num_CSTOREs++;

        if (unlikely(!dbg_have_cap_write))
        {
            tag_tracing_log_warning("Missing cap write info for STORE/CSTORE.");

            if (type == TAG_TRACING_TYPE_STORE) // equivalently: if (size < 16)
            {
                // NOTE even though capability info is missing, we know non-capability writes clears the tag
                static_assert(TAG_TRACING_TAG_CLEARED == 0, "cleared tag should be 0");
                trace_entry.tag_value = TAG_TRACING_TAG_CLEARED;

                dbg_stats.num_STOREs_missing_cap_info++;
            }
            else
            {
                tag_tracing_log_error("CSTORE with unknown tag value!.");

                static_assert(TAG_TRACING_TAG_UNKNOWN != 0 && TAG_TRACING_TAG_UNKNOWN != 1,
                    "unknown tags should not be confused with cleared or set tags");
                trace_entry.tag_value = TAG_TRACING_TAG_UNKNOWN;

                dbg_stats.num_CSTOREs_missing_cap_info++;
            }
        }
        else
        {
            if (unlikely(vaddr != cap_access_vaddr))
            {
                tag_tracing_log_error("Cap access info does not match expected for STORE/CSTORE.");
                fprintf(tag_tracing_dbg_logfile, "expected vaddr: " TARGET_FMT_lx ", vaddr: " TARGET_FMT_lx "\n",
                    cap_access_vaddr, vaddr);

                dbg_stats.num_impossible_errors++;
                return;
            }

            trace_entry.tag_value = cap_access_tag_value;
            trace_entry.paddr = cap_access_paddr;
        }

        dbg_have_cap_write = false;
    }
    else if (type == TAG_TRACING_TYPE_LOAD)
    {
        dbg_stats.num_LOADs++;

        if (unlikely(dbg_have_cap_write || dbg_have_cap_read))
        {
            // NOTE this only appears to happen for atomic instructions, which both read and write
            // TODO could add hardware address in there if we wanted
            tag_tracing_log_warning("Found cap access info for instruction with LOAD.");
        }
    }

    DynamorioTraceInterceptor::mem_logfile.write((char *) &trace_entry, sizeof(tag_tracing_entry_t));
}

EXTERN_C_END
