/*
 * QEMU RISC-V CPU
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "qemu/ctype.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "fpu/softfloat-helpers.h"
#include "sysemu/runstate.h"
#include "disas/disas.h"
#include "monitor/monitor.h"

#include "rvfi_dii.h"

#ifdef TARGET_CHERI
#include "cheri-lazy-capregs.h"
#endif

/* RISC-V CPU definitions */

static const char riscv_exts[26] = "IEMAFDQCLBJTPVNSUHKORWXYZG";

const char * const riscv_int_regnames[] = {
  "x0/zero", "x1/ra",  "x2/sp",  "x3/gp",  "x4/tp",  "x5/t0",   "x6/t1",
  "x7/t2",   "x8/s0",  "x9/s1",  "x10/a0", "x11/a1", "x12/a2",  "x13/a3",
  "x14/a4",  "x15/a5", "x16/a6", "x17/a7", "x18/s2", "x19/s3",  "x20/s4",
  "x21/s5",  "x22/s6", "x23/s7", "x24/s8", "x25/s9", "x26/s10", "x27/s11",
  "x28/t3",  "x29/t4", "x30/t5", "x31/t6"
};

const char * const riscv_fpr_regnames[] = {
  "f0/ft0",   "f1/ft1",  "f2/ft2",   "f3/ft3",   "f4/ft4",  "f5/ft5",
  "f6/ft6",   "f7/ft7",  "f8/fs0",   "f9/fs1",   "f10/fa0", "f11/fa1",
  "f12/fa2",  "f13/fa3", "f14/fa4",  "f15/fa5",  "f16/fa6", "f17/fa7",
  "f18/fs2",  "f19/fs3", "f20/fs4",  "f21/fs5",  "f22/fs6", "f23/fs7",
  "f24/fs8",  "f25/fs9", "f26/fs10", "f27/fs11", "f28/ft8", "f29/ft9",
  "f30/ft10", "f31/ft11"
};

const char * const riscv_excp_names[] = {
    "misaligned_fetch",
    "fault_fetch",
    "illegal_instruction",
    "breakpoint",
    "misaligned_load",
    "fault_load",
    "misaligned_store",
    "fault_store",
    "user_ecall",
    "supervisor_ecall",
    "hypervisor_ecall",
    "machine_ecall",
    "exec_page_fault",
    "load_page_fault",
    "reserved",
    "store_page_fault"
};

const char * const riscv_intr_names[] = {
    "u_software",
    "s_software",
    "h_software",
    "m_software",
    "u_timer",
    "s_timer",
    "h_timer",
    "m_timer",
    "u_external",
    "s_external",
    "h_external",
    "m_external",
    "reserved",
    "reserved",
    "reserved",
    "reserved"
};

static void set_misa(CPURISCVState *env, target_ulong misa)
{
    env->misa_mask = env->misa = misa;
}

static void set_priv_version(CPURISCVState *env, int priv_ver)
{
    env->priv_ver = priv_ver;
}

static void set_feature(CPURISCVState *env, int feature)
{
    env->features |= (1ULL << feature);
}

static void set_resetvec(CPURISCVState *env, int resetvec)
{
#ifndef CONFIG_USER_ONLY
    env->resetvec = resetvec;
#endif
}

static void riscv_any_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RVXLEN | RVI | RVM | RVA | RVF | RVD | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_11_0);
    set_resetvec(env, DEFAULT_RSTVEC);
}

#if defined(TARGET_RISCV32)

static void riscv_base32_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    /* We set this in the realise function */
    set_misa(env, 0);
}

static void rv32gcsu_priv1_09_1_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_09_1);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

static void rv32gcsu_priv1_10_0_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

static void rv32imacu_nommu_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_PMP);
}

#elif defined(TARGET_RISCV64)

static void riscv_base64_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    /* We set this in the realise function */
    set_misa(env, 0);
}

static void rv64gcsu_priv1_09_1_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_09_1);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

static void rv64gcsu_priv1_10_0_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

static void rv64imacu_nommu_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_PMP);
}

#endif

static ObjectClass *riscv_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;
    char **cpuname;

    cpuname = g_strsplit(cpu_model, ",", 1);
    typename = g_strdup_printf(RISCV_CPU_TYPE_NAME("%s"), cpuname[0]);
    oc = object_class_by_name(typename);
    g_strfreev(cpuname);
    g_free(typename);
    if (!oc || !object_class_dynamic_cast(oc, TYPE_RISCV_CPU) ||
        object_class_is_abstract(oc)) {
        return NULL;
    }
    return oc;
}

static void riscv_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    int i;

    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "pc      ", env->pc);
#ifndef CONFIG_USER_ONLY
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mhartid ", env->mhartid);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mstatus ", env->mstatus);
    qemu_fprintf(f, " %s 0x%x\n", "mip     ", env->mip);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mie     ", env->mie);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mideleg ", env->mideleg);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "medeleg ", env->medeleg);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtvec   ", env->mtvec);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mepc    ", env->mepc);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mcause  ", env->mcause);
#endif

    for (i = 0; i < 32; i++) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx,
                     riscv_int_regnames[i], gpr_int_value(env, i));
        if ((i & 3) == 3) {
            qemu_fprintf(f, "\n");
        }
    }
    if (flags & CPU_DUMP_FPU) {
        for (i = 0; i < 32; i++) {
            qemu_fprintf(f, " %s %016" PRIx64,
                         riscv_fpr_regnames[i], env->fpr[i]);
            if ((i & 3) == 3) {
                qemu_fprintf(f, "\n");
            }
        }
    }
}

static void riscv_cpu_set_pc(CPUState *cs, vaddr value)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    env->pc = value;
}

static void riscv_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    env->pc = tb->pc;
}

static bool riscv_cpu_has_work(CPUState *cs)
{
#ifndef CONFIG_USER_ONLY
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    /*
     * Definition of the WFI instruction requires it to ignore the privilege
     * mode and delegation registers, but respect individual enables
     */
    return (env->mip & env->mie) != 0;
#else
    return true;
#endif
}

void restore_state_to_opc(CPURISCVState *env, TranslationBlock *tb,
                          target_ulong *data)
{
    env->pc = data[0];
}


#ifdef CONFIG_RVFI_DII
extern int rvfi_client_fd;

static void rvfi_dii_send_trace(CPURISCVState* env, rvfi_dii_trace_t* trace)
{
    fprintf(stderr, "Sending %jd PCWD: 0x%08jx, RD: %02d, RWD: 0x%08jx, MA: 0x%08jx, MWD: 0x%08jx, MWM: 0x%08x, I: 0x%016jx\n",
            (uintmax_t)trace->rvfi_dii_order, (uintmax_t)trace->rvfi_dii_pc_wdata, trace->rvfi_dii_rd_addr, (uintmax_t)trace->rvfi_dii_rd_wdata,
            (uintmax_t)trace->rvfi_dii_mem_addr, (uintmax_t)trace->rvfi_dii_mem_wdata, trace->rvfi_dii_mem_wmask,
            (uintmax_t)trace->rvfi_dii_insn);
    ssize_t nbytes = write(rvfi_client_fd, trace, sizeof(*trace));
    if (nbytes != sizeof(*trace)) {
        error_report("Failed to write trace entry to socket: %zd (%s)", nbytes, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void rvfi_dii_communicate(CPUState* cs, CPURISCVState* env) {
    static bool rvfi_dii_started = false;
    // Single-step completed -> update PC in the trace buffer
    env->rvfi_dii_trace.rvfi_dii_pc_wdata = env->pc;
    env->rvfi_dii_trace.rvfi_dii_order++;

    // TestRIG expects a zero $pc after a trap:
    if (env->rvfi_dii_trace.rvfi_dii_trap) {
        info_report("Got trap at " TARGET_FMT_plx, env->pc);
    }
    env->rvfi_dii_have_injected_insn = false;
    while (true) {
        assert(cs->singlestep_enabled);
        rvfi_dii_command_t cmd_buf;
        _Static_assert(sizeof(cmd_buf) == 8, "Expected 8 bytes of data");
        if (rvfi_dii_started) {
            // Send previous state
            rvfi_dii_send_trace(env, &env->rvfi_dii_trace);
            // Zero the output trace for the next test except for instret
            uint64_t old_instret = env->rvfi_dii_trace.rvfi_dii_order;
            memset(&env->rvfi_dii_trace, 0, sizeof(env->rvfi_dii_trace));
            env->rvfi_dii_trace.rvfi_dii_order = old_instret;
        }
        // Should be blocking, so we only read fewer bytes on EOF
        ssize_t nbytes = read(rvfi_client_fd, &cmd_buf, sizeof(cmd_buf));
        if (nbytes != sizeof(cmd_buf)) {
            error_report("GOT EOF/Error reading from socket: %zd (%s)", nbytes,
                         strerror(errno));
            exit(EXIT_FAILURE);
        }
        info_report("Handling RVFI-DII command %d", cmd_buf.rvfi_dii_cmd);
        switch (cmd_buf.rvfi_dii_cmd) {
        case '\0': {
            env->rvfi_dii_trace.rvfi_dii_halt = 1;
            env->rvfi_dii_trace.rvfi_dii_order = 0;
            // Reset the processor (and ensure that it resets to 0x80000000
            cpu_reset(cs);
            // FIXME: Hopefully this resets RAM?
            qemu_system_reset(SHUTDOWN_CAUSE_HOST_SIGNAL);
            // Overwrite the processor's PC as the reset() writes it with default RSTVECTOR (0x10000)
            env->pc = 0x80000000;
            cs->cflags_next_tb |= CF_NOCACHE;
            hwaddr system_ram_addr;
            hwaddr system_ram_size;
            MemoryRegion *ram_region = address_space_translate(
                cs->as, cpu_get_phys_page_debug(cs, env->pc), &system_ram_addr,
                &system_ram_size, true, MEMTXATTRS_UNSPECIFIED);
            assert(system_ram_size == RVFI_DII_RAM_SIZE);
            // TODO: would be nice to do this lazily instead of writing 8 MiB
            memset(memory_region_get_ram_ptr(ram_region), 0, system_ram_size);
            // FIXME: is it safe to do a munmap/mmap?
            // Tell TCG that the data has changed
            memory_region_flush_ram(ram_region, system_ram_addr, system_ram_size);
            // TODO: if this is too fragile, we could do a address_space_write()/cpu_memory_rw_debug() loop
            break;
        }
        case 'B': {
            fprintf(stderr, "*BLINK*\n");
            info_report("*BLINK*\n");
            break;
        }
        case 'Q': {
            // The remote disconnected.
            fprintf(stderr, "Received a quit command. Quitting.\n");
            info_report("Received a quit command. Quitting.\n");
            close(rvfi_client_fd);
            rvfi_client_fd = 0;
            exit(EXIT_SUCCESS);
        }
        case 1: {
            cpu_single_step(cs, SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER);
            info_report("injecting instruction %d '0x%08x' at " TARGET_FMT_plx,
                        cmd_buf.rvfi_dii_time, cmd_buf.rvfi_dii_insn, env->pc);
            // Store the new code to the destination pointer
            cpu_memory_rw_debug(cs, env->pc, (uint8_t *)&cmd_buf.rvfi_dii_insn,
                                sizeof(cmd_buf.rvfi_dii_insn), true);
            // This is extremely important even though we don't use the value
            // written there in translate.c (since it can fail when env->pc is
            // an inaccessisible address such as 0x00000 on trap).
            // The reason we need this is that it ends up calling
            // tb_invalidate_phys_range() which flushes the cached translated
            // TCG blocks for that address.
            // Ideally we would just completely disable caching of translated
            // blocks in RVFI-DII mode, but I can't figure out how to do this.
#if 0
            uint32_t injected_inst = cpu_ldl_code(env, env->pc);
            if (injected_inst != cmd_buf.rvfi_dii_insn) {
                error_report("Failed to inject instruction '0x%08x' at "
                             "PC=" TARGET_FMT_plx " -- got '0x%08x' instead",
                             cmd_buf.rvfi_dii_insn, env->pc, injected_inst);
                exit(EXIT_FAILURE);
            }
#endif
            env->rvfi_dii_trace.rvfi_dii_insn = cmd_buf.rvfi_dii_insn;
            env->rvfi_dii_have_injected_insn = true;
            target_disas_buf(stderr, cs, &cmd_buf.rvfi_dii_insn,
                  sizeof(cmd_buf.rvfi_dii_insn), env->pc, 1);
            resume_all_vcpus();
            cpu_resume(cs);
            env->rvfi_dii_trace.rvfi_dii_pc_wdata = -1; // Will be set after single-step trap
            // Clear the EXCP_DEBUG flag to avoid dropping into GDB
            cs->exception_index = EXCP_NONE; // EXCP_INTERRUPT;
            rvfi_dii_started = true;
            cs->cflags_next_tb |= CF_NOCACHE;
            // Continue execution at env->pc
            cpu_loop_exit_noexc(cs); // noreturn -> jumps back to TCG
        }
        default:
            error_report("rvfi_dii got unsupported command '%c'\n",
                         cmd_buf.rvfi_dii_cmd);
            exit(EXIT_FAILURE);
        }
        rvfi_dii_started = true;
    }
}

#endif // CONFIG_RVFI_DII

static void riscv_debug_excp_handler(CPUState *cs)
{
    /*
     * Called by core code when a watchpoint or breakpoint fires;
     * Also happens for singlestep events
     */
#ifdef CONFIG_RVFI_DII
    struct RISCVCPU *cpu = RISCV_CPU(cs);
    struct CPURISCVState *env = &cpu->env;
    if (rvfi_client_fd && cs->singlestep_enabled) {
        rvfi_dii_communicate(cs, env);
        return;
    }
#endif
}

static void riscv_cpu_reset(CPUState *cs)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cpu);
    CPURISCVState *env = &cpu->env;

    mcc->parent_reset(cs);
#ifndef CONFIG_USER_ONLY
    env->priv = PRV_M;
    env->mstatus &= ~(MSTATUS_MIE | MSTATUS_MPRV);
    env->mcause = 0;
    env->pc = env->resetvec;
#endif
    cs->exception_index = EXCP_NONE;
    env->load_res = -1;
    set_default_nan_mode(1, &env->fp_status);

#if defined(TARGET_CHERI)
    // All general purpose capability registers are reset to NULL:
    reset_capregs(&env->gpcapregs);
    /*
     * See Table 5.2: Special Capability Registers (SCRs) in the CHERI ISA spec
     */
    // TODO: 0 Program counter cap. (PCC)
    // TODO: set_max_perms_capability(&env->PCC, env->resetvec);
    // 1 Default data cap. (DDC)
    set_max_perms_capability(&env->DDC, 0);
    // TODO:
    // 4 User trap code cap. (UTCC)
    // 5 User trap data cap. (UTDC)
    // 6 User scratch cap. (UScratchC)
    // 7 User exception PC cap. (UEPCC)
    // 12 Supervisor trap code cap. (STCC)
    // 13 Supervisor trap data cap. (STDC)
    // 14 Supervisor scratch cap. (SScratchC)
    // 15 Supervisor exception PC cap. (SEPCC)
    // 28 Machine trap code cap. (MTCC)
    // 29 Machine trap data cap. (MTDC)
    // 30 Machine scratch cap. (MScratchC)
    // 31 Machine exception PC cap. (MEPCC)
#endif /* TARGET_CHERI */
}

static void riscv_cpu_disas_set_info(CPUState *s, disassemble_info *info)
{
#if defined(TARGET_RISCV32)
    info->print_insn = print_insn_riscv32;
#elif defined(TARGET_RISCV64)
    info->print_insn = print_insn_riscv64;
#endif
}

static void riscv_cpu_realize(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    RISCVCPU *cpu = RISCV_CPU(dev);
    CPURISCVState *env = &cpu->env;
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(dev);
    int priv_version = PRIV_VERSION_1_11_0;
    target_ulong target_misa = 0;
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    if (cpu->cfg.priv_spec) {
        if (!g_strcmp0(cpu->cfg.priv_spec, "v1.11.0")) {
            priv_version = PRIV_VERSION_1_11_0;
        } else if (!g_strcmp0(cpu->cfg.priv_spec, "v1.10.0")) {
            priv_version = PRIV_VERSION_1_10_0;
        } else if (!g_strcmp0(cpu->cfg.priv_spec, "v1.9.1")) {
            priv_version = PRIV_VERSION_1_09_1;
        } else {
            error_setg(errp,
                       "Unsupported privilege spec version '%s'",
                       cpu->cfg.priv_spec);
            return;
        }
    }

    set_priv_version(env, priv_version);
    set_resetvec(env, DEFAULT_RSTVEC);

    if (cpu->cfg.mmu) {
        set_feature(env, RISCV_FEATURE_MMU);
    }

    if (cpu->cfg.pmp) {
        set_feature(env, RISCV_FEATURE_PMP);
    }

    /* If misa isn't set (rv32 and rv64 machines) set it here */
    if (!env->misa) {
        /* Do some ISA extension error checking */
        if (cpu->cfg.ext_i && cpu->cfg.ext_e) {
            error_setg(errp,
                       "I and E extensions are incompatible");
                       return;
       }

        if (!cpu->cfg.ext_i && !cpu->cfg.ext_e) {
            error_setg(errp,
                       "Either I or E extension must be set");
                       return;
       }

       if (cpu->cfg.ext_g && !(cpu->cfg.ext_i & cpu->cfg.ext_m &
                               cpu->cfg.ext_a & cpu->cfg.ext_f &
                               cpu->cfg.ext_d)) {
            warn_report("Setting G will also set IMAFD");
            cpu->cfg.ext_i = true;
            cpu->cfg.ext_m = true;
            cpu->cfg.ext_a = true;
            cpu->cfg.ext_f = true;
            cpu->cfg.ext_d = true;
        }

        /* Set the ISA extensions, checks should have happened above */
        if (cpu->cfg.ext_i) {
            target_misa |= RVI;
        }
        if (cpu->cfg.ext_e) {
            target_misa |= RVE;
        }
        if (cpu->cfg.ext_m) {
            target_misa |= RVM;
        }
        if (cpu->cfg.ext_a) {
            target_misa |= RVA;
        }
        if (cpu->cfg.ext_f) {
            target_misa |= RVF;
        }
        if (cpu->cfg.ext_d) {
            target_misa |= RVD;
        }
        if (cpu->cfg.ext_c) {
            target_misa |= RVC;
        }
        if (cpu->cfg.ext_s) {
            target_misa |= RVS;
        }
        if (cpu->cfg.ext_u) {
            target_misa |= RVU;
        }

        set_misa(env, RVXLEN | target_misa);
    }

    riscv_cpu_register_gdb_regs_for_features(cs);

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    mcc->parent_realize(dev, errp);
}

static void riscv_cpu_init(Object *obj)
{
    RISCVCPU *cpu = RISCV_CPU(obj);

    cpu_set_cpustate_pointers(cpu);
}

static const VMStateDescription vmstate_riscv_cpu = {
    .name = "cpu",
    .unmigratable = 1,
};

static Property riscv_cpu_properties[] = {
    DEFINE_PROP_BOOL("i", RISCVCPU, cfg.ext_i, true),
    DEFINE_PROP_BOOL("e", RISCVCPU, cfg.ext_e, false),
    DEFINE_PROP_BOOL("g", RISCVCPU, cfg.ext_g, true),
    DEFINE_PROP_BOOL("m", RISCVCPU, cfg.ext_m, true),
    DEFINE_PROP_BOOL("a", RISCVCPU, cfg.ext_a, true),
    DEFINE_PROP_BOOL("f", RISCVCPU, cfg.ext_f, true),
    DEFINE_PROP_BOOL("d", RISCVCPU, cfg.ext_d, true),
    DEFINE_PROP_BOOL("c", RISCVCPU, cfg.ext_c, true),
    DEFINE_PROP_BOOL("s", RISCVCPU, cfg.ext_s, true),
    DEFINE_PROP_BOOL("u", RISCVCPU, cfg.ext_u, true),
    DEFINE_PROP_BOOL("Counters", RISCVCPU, cfg.ext_counters, true),
    DEFINE_PROP_BOOL("Zifencei", RISCVCPU, cfg.ext_ifencei, true),
    DEFINE_PROP_BOOL("Zicsr", RISCVCPU, cfg.ext_icsr, true),
    DEFINE_PROP_STRING("priv_spec", RISCVCPU, cfg.priv_spec),
    DEFINE_PROP_BOOL("mmu", RISCVCPU, cfg.mmu, true),
    DEFINE_PROP_BOOL("pmp", RISCVCPU, cfg.pmp, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void riscv_cpu_class_init(ObjectClass *c, void *data)
{
    RISCVCPUClass *mcc = RISCV_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);
    DeviceClass *dc = DEVICE_CLASS(c);

    device_class_set_parent_realize(dc, riscv_cpu_realize,
                                    &mcc->parent_realize);

    cpu_class_set_parent_reset(cc, riscv_cpu_reset, &mcc->parent_reset);

    cc->class_by_name = riscv_cpu_class_by_name;
    cc->has_work = riscv_cpu_has_work;
    cc->do_interrupt = riscv_cpu_do_interrupt;
    cc->cpu_exec_interrupt = riscv_cpu_exec_interrupt;
    cc->dump_state = riscv_cpu_dump_state;
    cc->set_pc = riscv_cpu_set_pc;
    cc->synchronize_from_tb = riscv_cpu_synchronize_from_tb;
    cc->gdb_read_register = riscv_cpu_gdb_read_register;
    cc->gdb_write_register = riscv_cpu_gdb_write_register;
    cc->gdb_num_core_regs = 33;
#if defined(TARGET_RISCV32)
    cc->gdb_core_xml_file = "riscv-32bit-cpu.xml";
#elif defined(TARGET_RISCV64)
    cc->gdb_core_xml_file = "riscv-64bit-cpu.xml";
#endif
    cc->gdb_stop_before_watchpoint = true;
    cc->disas_set_info = riscv_cpu_disas_set_info;
#ifndef CONFIG_USER_ONLY
    cc->do_transaction_failed = riscv_cpu_do_transaction_failed;
    cc->do_unaligned_access = riscv_cpu_do_unaligned_access;
    cc->get_phys_page_debug = riscv_cpu_get_phys_page_debug;
#endif
#ifdef CONFIG_TCG
    cc->tcg_initialize = riscv_translate_init;
    cc->tlb_fill = riscv_cpu_tlb_fill;
    cc->debug_excp_handler = riscv_debug_excp_handler;
#endif
    /* For now, mark unmigratable: */
    cc->vmsd = &vmstate_riscv_cpu;
    device_class_set_props(dc, riscv_cpu_properties);
}

char *riscv_isa_string(RISCVCPU *cpu)
{
    int i;
    const size_t maxlen = sizeof("rv128") + sizeof(riscv_exts) + 1;
    char *isa_str = g_new(char, maxlen);
    char *p = isa_str + snprintf(isa_str, maxlen, "rv%d", TARGET_LONG_BITS);
    for (i = 0; i < sizeof(riscv_exts); i++) {
        if (cpu->env.misa & RV(riscv_exts[i])) {
            *p++ = qemu_tolower(riscv_exts[i]);
        }
    }
    *p = '\0';
    return isa_str;
}

static gint riscv_cpu_list_compare(gconstpointer a, gconstpointer b)
{
    ObjectClass *class_a = (ObjectClass *)a;
    ObjectClass *class_b = (ObjectClass *)b;
    const char *name_a, *name_b;

    name_a = object_class_get_name(class_a);
    name_b = object_class_get_name(class_b);
    return strcmp(name_a, name_b);
}

static void riscv_cpu_list_entry(gpointer data, gpointer user_data)
{
    const char *typename = object_class_get_name(OBJECT_CLASS(data));
    int len = strlen(typename) - strlen(RISCV_CPU_TYPE_SUFFIX);

    qemu_printf("%.*s\n", len, typename);
}

void riscv_cpu_list(void)
{
    GSList *list;

    list = object_class_get_list(TYPE_RISCV_CPU, false);
    list = g_slist_sort(list, riscv_cpu_list_compare);
    g_slist_foreach(list, riscv_cpu_list_entry, NULL);
    g_slist_free(list);
}

#define DEFINE_CPU(type_name, initfn)      \
    {                                      \
        .name = type_name,                 \
        .parent = TYPE_RISCV_CPU,          \
        .instance_init = initfn            \
    }

static const TypeInfo riscv_cpu_type_infos[] = {
    {
        .name = TYPE_RISCV_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(RISCVCPU),
        .instance_init = riscv_cpu_init,
        .abstract = true,
        .class_size = sizeof(RISCVCPUClass),
        .class_init = riscv_cpu_class_init,
    },
    DEFINE_CPU(TYPE_RISCV_CPU_ANY,              riscv_any_cpu_init),
#if defined(TARGET_RISCV32)
    DEFINE_CPU(TYPE_RISCV_CPU_BASE32,           riscv_base32_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E31,       rv32imacu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U34,       rv32gcsu_priv1_10_0_cpu_init),
    /* Depreacted */
    DEFINE_CPU(TYPE_RISCV_CPU_RV32IMACU_NOMMU,  rv32imacu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_RV32GCSU_V1_09_1, rv32gcsu_priv1_09_1_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_RV32GCSU_V1_10_0, rv32gcsu_priv1_10_0_cpu_init)
#elif defined(TARGET_RISCV64)
    DEFINE_CPU(TYPE_RISCV_CPU_BASE64,           riscv_base64_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E51,       rv64imacu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U54,       rv64gcsu_priv1_10_0_cpu_init),
    /* Deprecated */
    DEFINE_CPU(TYPE_RISCV_CPU_RV64IMACU_NOMMU,  rv64imacu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_RV64GCSU_V1_09_1, rv64gcsu_priv1_09_1_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_RV64GCSU_V1_10_0, rv64gcsu_priv1_10_0_cpu_init)
#endif
};

DEFINE_TYPES(riscv_cpu_type_infos)
