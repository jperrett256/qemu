#include "trace_extra/tag_tracing.h"
#include "trace_extra/memory_interceptor.hh"

EXTERN_C

FILE * tag_tracing_dbg_logfile;

void tag_tracing_write_entry(tag_tracing_entry_t * entry)
{
	// TODO then try using within memory_interceptor.cc, then see if you can output from cheri_tagmem.c
	// TODO need to worry about ordering?
	DynamorioTraceInterceptor::mem_logfile.write((char *) entry, sizeof(tag_tracing_entry_t));
}

EXTERN_C_END
