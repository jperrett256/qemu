/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Mingle Chen
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under Defense Advanced Research Projects Agency (DARPA)
 * Contract No. HR001122C0110 ("ETC").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include "trace_extra/tag_tracing.h"
#include "trace_extra/memory_interceptor.hh"

DynamorioTraceInterceptor::ThreadLocalState::ThreadLocalState(
    ThreadLocalStateArgs &)
{
}

io::filtering_ostream DynamorioTraceInterceptor::mem_logfile;

void DynamorioTraceInterceptor::OnTracePacket(InterceptorContext context)
{
    perfetto::protos::pbzero::TracePacket::Decoder packet(context.packet_data.data, context.packet_data.size);
    if (packet.has_track_event()) {
        perfetto::protos::pbzero::TrackEvent::Decoder track_event(packet.track_event());
        if (track_event.has_qemu()) {
            perfetto::protos::pbzero::QEMUEventInfo::Decoder qemu(track_event.qemu());
            if (qemu.has_instr()) {
                perfetto::protos::pbzero::QEMULogEntry::Decoder instr(qemu.instr());

#ifdef TAG_TRACING_DBG_LOG
                fprintf(tag_tracing_dbg_logfile, "INSTRUCTION BOUNDARY\n");
#endif

                if (instr.has_pc() && instr.has_opcode_obj()) {
                    perfetto::protos::pbzero::Opcode::Decoder opcode(instr.opcode_obj());

                    if (opcode.has_size()) {
#ifdef TAG_TRACING_DBG_LOG
                        fprintf(tag_tracing_dbg_logfile, "Instruction [size: %d, vaddr: " TARGET_FMT_lx ", opcode: ",
                            opcode.size(), instr.pc());
                        uint64_t opcode_bytes = opcode.has_value() ? opcode.value() : 0;
                        for (int i = 0; i < opcode.size(); i++)
                        {
                            fprintf(tag_tracing_dbg_logfile, "%02x", ((uint8_t *) &opcode_bytes)[i]);
                        }
                        fprintf(tag_tracing_dbg_logfile, " ]\n");
#endif
                        tag_tracing_emit_entry(TAG_TRACING_TYPE_INSTR, opcode.size(), instr.pc());
                    }
                }
                if (instr.has_mem()) {
                    for (auto iter = instr.mem(); iter; iter++) {
                        perfetto::protos::pbzero::QEMULogEntryMem::Decoder mem(*iter);

                        bool dbg_type_valid = true;
                        tag_tracing_type_t entry_type;
                        switch (mem.op()) {
                            case perfetto::protos::pbzero::QEMULogEntryMem_MemOp_LOAD:
                                entry_type = TAG_TRACING_TYPE_LOAD;
                                break;
                            case perfetto::protos::pbzero::QEMULogEntryMem_MemOp_CLOAD:
                                entry_type = TAG_TRACING_TYPE_CLOAD;
                                break;
                            case perfetto::protos::pbzero::QEMULogEntryMem_MemOp_STORE:
                                entry_type = TAG_TRACING_TYPE_STORE;
                                break;
                            case perfetto::protos::pbzero::QEMULogEntryMem_MemOp_CSTORE:
                                entry_type = TAG_TRACING_TYPE_CSTORE;
                                break;
                            default:
                                dbg_type_valid = false;
                                break;
                        }

                        if (!dbg_type_valid)
                        {
                            fprintf(tag_tracing_dbg_logfile, "ERROR: invalid memory operation\n");
                            continue;
                        }

#ifdef TAG_TRACING_DBG_LOG
                        fprintf(tag_tracing_dbg_logfile, "Data access [type: %s, size: %d, vaddr: " TARGET_FMT_lx "]\n",
                            mem.op() == perfetto::protos::pbzero::QEMULogEntryMem_MemOp_LOAD ? "LOAD" :
                            mem.op() == perfetto::protos::pbzero::QEMULogEntryMem_MemOp_CLOAD ? "CLOAD" :
                            mem.op() == perfetto::protos::pbzero::QEMULogEntryMem_MemOp_STORE ? "STORE" :
                            mem.op() == perfetto::protos::pbzero::QEMULogEntryMem_MemOp_CSTORE ? "CSTORE" : "UNKOWN",
                            mem.size(), mem.addr());
#endif
                        tag_tracing_emit_entry(entry_type, mem.size(), mem.addr());
                    }
                }

                tag_tracing_end_instr();
            }
        }
    }
}
