#pragma once

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
#define EXTERN_C extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C
#define EXTERN_C_END
#endif

#ifndef TARGET_FMT_lx
#define TARGET_FMT_lx "%016" PRIx64
#endif

enum tag_tracing_type_t
{
	TAG_TRACING_TYPE_INSTR,
	TAG_TRACING_TYPE_LOAD,
	TAG_TRACING_TYPE_STORE,
	TAG_TRACING_TYPE_CLOAD,
	TAG_TRACING_TYPE_CSTORE,
};

typedef struct tag_tracing_entry_t tag_tracing_entry_t;
struct tag_tracing_entry_t
{
	uint8_t type;
	uint8_t tag_value; // only applicable for CSTOREs/STOREs
	uintptr_t virt_addr; // TODO may only need to keep for CSTORE/STOREs? (Check we don't need the CLOADs to reconstruct mapping)
	uintptr_t hw_addr;
};

EXTERN_C
extern FILE * tag_tracing_dbg_logfile;
void tag_tracing_write_entry(tag_tracing_entry_t * entry);
EXTERN_C_END
