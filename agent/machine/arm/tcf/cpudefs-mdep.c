/*******************************************************************************
 * Copyright (c) 2013 Stanislav Yakovlev and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Stanislav Yakovlev           - initial API and implementation
 *     Emmanuel Touron (Wind River) - initial ARM stepping emulation
 *     Stanislav Yakovlev           - [404627] Add support for ARM VFP registers
 *******************************************************************************/

#include <tcf/config.h>

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/trace.h>
#include <tcf/services/symbols.h>
#include <tcf/services/runctrl.h>
#include <machine/arm/tcf/disassembler-arm.h>
#include <machine/arm/tcf/stack-crawl-arm.h>
#include <tcf/cpudefs-mdep.h>

#define REG_OFFSET(name) offsetof(REG_SET, name)

RegisterDefinition regs_def[] = {
#   define REG_FP user.regs.uregs[11]
#   define REG_SP user.regs.uregs[13]
#   define REG_PC user.regs.uregs[15]
#   define REG_CPSR user.regs.uregs[16]
    { "r0",      REG_OFFSET(user.regs.uregs[0]),      4, 0, 0},
    { "r1",      REG_OFFSET(user.regs.uregs[1]),      4, 1, 1},
    { "r2",      REG_OFFSET(user.regs.uregs[2]),      4, 2, 2},
    { "r3",      REG_OFFSET(user.regs.uregs[3]),      4, 3, 3},
    { "r4",      REG_OFFSET(user.regs.uregs[4]),      4, 4, 4},
    { "r5",      REG_OFFSET(user.regs.uregs[5]),      4, 5, 5},
    { "r6",      REG_OFFSET(user.regs.uregs[6]),      4, 6, 6},
    { "r7",      REG_OFFSET(user.regs.uregs[7]),      4, 7, 7},
    { "r8",      REG_OFFSET(user.regs.uregs[8]),      4, 8, 8},
    { "r9",      REG_OFFSET(user.regs.uregs[9]),      4, 9, 9},
    { "r10",     REG_OFFSET(user.regs.uregs[10]),     4, 10, 10},
    { "fp",      REG_OFFSET(user.regs.uregs[11]),     4, 11, 11},
    { "ip",      REG_OFFSET(user.regs.uregs[12]),     4, 12, 12},
    { "sp",      REG_OFFSET(user.regs.uregs[13]),     4, 13, 13},
    { "lr",      REG_OFFSET(user.regs.uregs[14]),     4, 14, 14},
    { "pc",      REG_OFFSET(user.regs.uregs[15]),     4, 15, 15},
    { "cpsr",    REG_OFFSET(user.regs.uregs[16]),     4, -1, -1},
    { "orig_r0", REG_OFFSET(user.regs.uregs[17]),     4, -1, -1},
    { "vfp",     0, 0, -1, -1, 0, 0, 1, 1 },
    { NULL,      0, 0,  0,  0},
};

RegisterDefinition * regs_index = NULL;
static unsigned regs_cnt = 0;
static unsigned regs_max = 0;

unsigned char BREAK_INST[] = { 0xf0, 0x01, 0xf0, 0xe7 };

static RegisterDefinition * pc_def = NULL;
static RegisterDefinition * lr_def = NULL;
static RegisterDefinition * cpsr_def = NULL;

#include <sys/ptrace.h>

#if !defined(PTRACE_GETHBPREGS)
#define PTRACE_GETHBPREGS 29
#endif
#if !defined(PTRACE_SETHBPREGS)
#define PTRACE_SETHBPREGS 30
#endif

typedef struct ContextExtensionARM {
    int sw_stepping;
    char opcode[sizeof(BREAK_INST)];
    ContextAddress addr;

#if ENABLE_HardwareBreakpoints
#define MAX_HBP 16
#define MAX_HWP 16
#define MAX_HW_BPS (MAX_HBP + MAX_HWP)
    uint8_t arch;
    uint8_t wp_size;
    uint8_t wp_cnt;
    uint8_t bp_cnt;
    int8_t info_ok;
    int hw_stepping;

    ContextBreakpoint * triggered_hw_bps[MAX_HW_BPS + 1];
    unsigned hw_bps_regs_generation;

    ContextBreakpoint * hw_bps[MAX_HW_BPS];
    unsigned hw_bps_generation;

    unsigned armed;
#endif
} ContextExtensionARM;

static size_t context_extension_offset = 0;

#define EXT(ctx) ((ContextExtensionARM *)((char *)(ctx) + context_extension_offset))

static int arm_get_next_address(Context * ctx, ContextAddress * next_addr);

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return pc_def;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return crawl_stack_frame_arm(frame, down);
}

void add_cpudefs_disassembler(Context * cpu_ctx) {
    add_disassembler(cpu_ctx, "ARM", disassemble_arm);
    add_disassembler(cpu_ctx, "Thumb", disassemble_thumb);
}

static int read_reg(Context *ctx, RegisterDefinition * def, size_t size, ContextAddress * addr) {
    size_t i;
    uint8_t buf[8];
    uint64_t n = 0;
    *addr = 0;
    assert(!def->big_endian);
    assert(size <= def->size);
    assert(size <= sizeof(buf));
    if (context_read_reg(ctx, def, 0, size, buf) < 0) return -1;
    for (i = 0; i < size; i++) n |= (uint64_t)buf[i] << (i * 8);
    *addr = (ContextAddress)n;
    return 0;
}

#if ENABLE_HardwareBreakpoints

static void clear_bp(ContextBreakpoint * bp) {
    unsigned i;
    Context * ctx = bp->ctx;
    ContextExtensionARM * bps = EXT(ctx);
    for (i = 0; i < MAX_HW_BPS; i++) {
        if (bps->hw_bps[i] == bp) bps->hw_bps[i] = NULL;
    }
}

static int get_bp_info(Context * ctx) {
    uint32_t buf = 0;
    ContextExtensionARM * bps = EXT(ctx);
    if (bps->info_ok) return 0;
    if (ptrace(PTRACE_GETHBPREGS, id2pid(ctx->id, NULL), 0, &buf) < 0) return -1;
    bps->arch = (uint8_t)(buf >> 24);
    bps->wp_size = (uint8_t)(buf >> 16);
    bps->wp_cnt = (uint8_t)(buf >> 8);
    bps->bp_cnt = (uint8_t)buf;
    if (bps->wp_cnt > MAX_HWP) bps->wp_cnt = MAX_HWP;
    if (bps->bp_cnt > MAX_HBP) bps->bp_cnt = MAX_HBP;
    bps->info_ok = 1;
    return 0;
}

static int set_debug_regs(Context * ctx, int * step_over_hw_bp) {
    int i, j;
    ContextAddress pc = 0;
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT);
    ContextExtensionARM * ext = EXT(ctx);
    ContextExtensionARM * bps = EXT(grp);
    pid_t pid = id2pid(ctx->id, NULL);

    assert(bps->info_ok);

    ext->armed = 0;
    *step_over_hw_bp = 0;
    if (read_reg(ctx, pc_def, pc_def->size, &pc) < 0) return -1;

    for (i = 0; i < bps->bp_cnt + bps->wp_cnt; i++) {
        uint32_t cr = 0;
        ContextBreakpoint * cb = bps->hw_bps[i];
        if (i == 0 && ext->hw_stepping) {
            uint32_t vr = 0;
            if (ext->hw_stepping == 1) {
                vr = (uint32_t)ext->addr;
            }
            else {
                vr = (uint32_t)pc;
                cr |= 1u << 22;
            }
            cr |= 0xfu << 5;
            cr |= 0x7u;
            if (ptrace(PTRACE_SETHBPREGS, pid, 1, &vr) < 0) return -1;
        }
        else if (cb != NULL) {
            if (i < bps->bp_cnt && cb->address == pc) {
                /* Skipping the breakpoint */
                *step_over_hw_bp = 1;
            }
            else {
                uint32_t vr = (uint32_t)(cb->address & ~3);
                if (i < bps->bp_cnt) {
                    cr |= 0xfu << 5;
                }
                else {
                    for (j = 0; j < 4; j++) {
                        if (vr + j < cb->address) continue;
                        if (vr + j >= cb->address + cb->length) continue;
                        cr |= 1 << (5 + j);
                    }
                    if (cb->access_types & CTX_BP_ACCESS_DATA_READ) cr |= 1 << 3;
                    if (cb->access_types & CTX_BP_ACCESS_DATA_WRITE) cr |= 1 << 4;
                }
                cr |= 0x7u;
                if (i < bps->bp_cnt) {
                    if (ptrace(PTRACE_SETHBPREGS, pid, i * 2 + 1, &vr) < 0) return -1;
                }
                else {
                    if (ptrace(PTRACE_SETHBPREGS, pid, -(i * 2 + 1), &vr) < 0) return -1;
                }
                ext->armed |= 1u << i;
            }
        }
        if (cr == 0) {
            /* Linux kernel does not allow 0 as Control Register value */
            cr |= 0x3u << 1;
            cr |= 0xfu << 5;
            if (i >= bps->bp_cnt) {
                cr |= 1u << 4;
            }
        }
        if (i < bps->bp_cnt) {
            if (ptrace(PTRACE_SETHBPREGS, pid, i * 2 + 2, &cr) < 0) return -1;
        }
        else {
            if (ptrace(PTRACE_SETHBPREGS, pid, -(i * 2 + 2), &cr) < 0) return -1;
        }
    }

    ext->hw_bps_regs_generation = bps->hw_bps_generation;
    return 0;
}

static int enable_hw_stepping_mode(Context * ctx, int mode) {
    int step = 0;
    ContextExtensionARM * ext = EXT(ctx);
    if (mode == 1 && arm_get_next_address(ctx, &ext->addr) < 0) return -1;
    ext->hw_stepping = mode;
    return set_debug_regs(ctx, &step);
}

static int disable_hw_stepping_mode(Context * ctx) {
    ContextExtensionARM * ext = EXT(ctx);
    ext->hw_stepping = 0;
    ext->hw_bps_regs_generation--;
    return 0;
}

int cpu_bp_get_capabilities(Context * ctx) {
    int res = 0;
    ContextExtensionARM * bps = EXT(ctx);
    if (ctx != context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT)) return 0;
    if (get_bp_info(ctx) < 0) return 0;
    if (bps->bp_cnt > 0) {
        res |= CTX_BP_ACCESS_INSTRUCTION;
    }
    if (bps->wp_cnt > 0) {
        res |= CTX_BP_ACCESS_DATA_READ;
        res |= CTX_BP_ACCESS_DATA_WRITE;
    }
    res |= CTX_BP_ACCESS_VIRTUAL;
    return res;
}

int cpu_bp_plant(ContextBreakpoint * bp) {
    Context * ctx = bp->ctx;
    ContextExtensionARM * bps = EXT(ctx);
    assert(bp->access_types);
    assert(ctx == context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
    if (get_bp_info(ctx) < 0) return -1;
    if (bp->access_types & CTX_BP_ACCESS_VIRTUAL) {
        if (bp->access_types & CTX_BP_ACCESS_INSTRUCTION) {
            unsigned i;
            unsigned n = 0;
            for (i = 0; i < bps->bp_cnt; i++) {
                assert(bps->hw_bps[i] != bp);
                if (bps->hw_bps[i] == NULL) {
                    bps->hw_bps[i] = bp;
                    bps->hw_bps_generation++;
                    n++;
                    break;
                }
            }
            if (n == 0) {
                clear_bp(bp);
                errno = ERR_UNSUPPORTED;
                return -1;
            }
        }
        if (bp->access_types & (CTX_BP_ACCESS_DATA_READ | CTX_BP_ACCESS_DATA_WRITE)) {
            unsigned n = 0;
            if (bp->length <= bps->wp_size) {
                unsigned i;
                for (i = bps->bp_cnt; i < bps->bp_cnt + bps->wp_cnt; i++) {
                    assert(bps->hw_bps[i] != bp);
                    if (bps->hw_bps[i] == NULL) {
                        bps->hw_bps[i] = bp;
                        bps->hw_bps_generation++;
                        n++;
                        break;
                    }
                }
            }
            if (n == 0) {
                clear_bp(bp);
                errno = ERR_UNSUPPORTED;
                return -1;
            }
        }
        return 0;
    }
    errno = ERR_UNSUPPORTED;
    return -1;
}

int cpu_bp_remove(ContextBreakpoint * bp) {
    ContextExtensionARM * bps = EXT(bp->ctx);
    clear_bp(bp);
    bps->hw_bps_generation++;
    return 0;
}

int cpu_bp_on_resume(Context * ctx, int * single_step) {
    ContextExtensionARM * ext = EXT(ctx);
    ContextExtensionARM * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
    if (ctx->stopped_by_cb != NULL || ext->hw_bps_regs_generation != bps->hw_bps_generation) {
        if (set_debug_regs(ctx, single_step) < 0) return -1;
    }
    return 0;
}

int cpu_bp_on_suspend(Context * ctx, int * triggered) {
    unsigned cb_cnt = 0;
    ContextExtensionARM * ext = EXT(ctx);
    ContextExtensionARM * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
    int i;

    if (ctx->exiting) return 0;

    if (bps->bp_cnt > 0) {
        ContextAddress pc = 0;
        if (read_reg(ctx, pc_def, pc_def->size, &pc) < 0) return -1;
        for (i = 0; i < bps->bp_cnt; i++) {
            ContextBreakpoint * cb = bps->hw_bps[i];
            if (cb != NULL && cb->address == pc && (ext->armed & (1u << i))) {
                ext->triggered_hw_bps[cb_cnt++] = cb;
            }
        }
    }

    if (bps->wp_cnt > 0) {
        siginfo_t siginfo;
        pid_t pid = id2pid(ctx->id, NULL);
        if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) < 0) return -1;
        if (siginfo.si_signo == SIGTRAP && (siginfo.si_code & 0xffff) == 0x0004 && siginfo.si_errno < 0) {
            /* Watchpoint */
            for (i = bps->bp_cnt; i < bps->bp_cnt + bps->wp_cnt; i++) {
                ContextBreakpoint * cb = bps->hw_bps[i];
                if (cb != NULL && (ext->armed & (1u << i))) {
                    if (bps->wp_cnt > 1) {
                        ContextAddress addr = (ContextAddress)siginfo.si_addr;
                        if (addr < cb->address || addr >= cb->address + cb->length) continue;
                    }
                    ext->triggered_hw_bps[cb_cnt++] = cb;
                }
            }
        }
    }

    *triggered = cb_cnt > 0;
    if (cb_cnt > 0) {
        ctx->stopped_by_cb = ext->triggered_hw_bps;
        ctx->stopped_by_cb[cb_cnt] = NULL;
    }
    return 0;
}

#endif /* ENABLE_HardwareBreakpoints */

static Context * arm_ctx;
static uint32_t arm_pc;
static uint32_t arm_instr;
static uint32_t arm_cpsr;
static uint32_t arm_next;
static int arm_cond;

static int arm_evaluate_condition(void) {
    int N = ( arm_cpsr >> 31 ) & 1;
    int Z = ( arm_cpsr >> 30 ) & 1;
    int C = ( arm_cpsr >> 29 ) & 1;
    int V = ( arm_cpsr >> 28 ) & 1;

    switch (arm_instr >> 28) {
    case 0 : return Z;
    case 1 : return Z == 0;
    case 2 : return C;
    case 3 : return C == 0;
    case 4 : return N;
    case 5 : return N == 0;
    case 6 : return V;
    case 7 : return V == 0;
    case 8 : return C == 0 && Z == 0;
    case 9 : return C == 0 || Z == 1;
    case 10: return N == V;
    case 11: return N != V;
    case 12: return Z == 0 && N == V;
    case 13: return Z == 1 || N != V;
    }

    return 1;
}

static int arm_get_next_bx(void) {
    uint32_t Rm = arm_instr & 0xf;
    if (arm_cond == 0) return 0;
    return context_read_reg(arm_ctx, regs_index + Rm, 0, 4, &arm_next);
}

static int arm_get_next_ldm(void) {
    int P = (arm_instr & (1 << 24)) != 0;
    int U = (arm_instr & (1 << 23)) != 0;
    int S = (arm_instr & (1 << 22)) != 0;
    int L = (arm_instr & (1 << 20)) != 0;
    uint32_t Rn = (arm_instr >> 16) & 0xf;
    ContextAddress addr = 0;

    if (((arm_instr >> 28) & 0xf) == 0xf) return 0;
    if (!L || S || Rn == 15) return 0;
    if ((arm_instr & (1 << 15)) == 0) return 0;
    if (arm_cond == 0) return 0;

    if (read_reg(arm_ctx, regs_index + Rn, 4, &addr) < 0) return -1;
    if (U) {
        int i;
        for (i = 0; i < 15; i++) {
            if (arm_instr & (1 << i)) addr += 4;
        }
    }
    if (P) addr = U ? addr + 4 : addr - 4;
    return context_read_mem(arm_ctx, addr, &arm_next, 4);
}

static int arm_get_next_branch(void) {
    int32_t imm = arm_instr & 0x00FFFFFF;
    if (arm_cond == 0) return 0;
    if (imm & 0x00800000) imm |= 0xFF000000;
    imm = imm << 2;
    arm_next = ((int)arm_pc + imm + 8);
    return 0;
}

static int arm_get_next_address(Context * ctx, ContextAddress * next_addr) {
    ContextAddress addr = 0;
    ContextAddress cpsr = 0;

    /* read opcode at PC */
    if (read_reg(ctx, pc_def, pc_def->size, &addr) < 0) return -1;
    if (read_reg(ctx, cpsr_def, cpsr_def->size, &cpsr) < 0) return -1;
    if (context_read_mem(ctx, addr, &arm_instr, 4) < 0) return -1;

    arm_ctx = ctx;
    arm_pc = (uint32_t)addr;
    arm_cpsr = (uint32_t)cpsr;
    trace(LOG_CONTEXT, "pc 0x%x, opcode 0x%x", arm_pc, arm_instr);

    /* decode opcode */
    arm_cond = arm_evaluate_condition();

    arm_next = arm_pc + 4;
    switch ((arm_instr >> 25) & 7) {
    case 0:
        if ((arm_instr & 0xfffffff0) == 0xe12fff10) {
            /* Branch and Exchange */
            if (arm_get_next_bx() < 0) return -1;
            break;
        }
        break;
    case 4: /* Load/store multiple */
        if (arm_get_next_ldm() < 0) return -1;
        break;
    case 5: /* Branch and branch with link */
        if (arm_get_next_branch() < 0) return -1;
        break;
    }
    /* TODO: add/sub pc, ldr pc */

    addr = arm_next;
    if (addr >= 0xffff0000) {
        /* Linux kernel user-mode helpers space - run to return address */
        if (read_reg(ctx, lr_def, lr_def->size, &addr) < 0) return -1;
    }
    *next_addr = addr;
    return 0;
}

static int enable_sw_stepping_mode(Context * ctx) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionARM * ext = EXT(grp);
    assert(!grp->exited);
    assert(!ext->sw_stepping);
    if (arm_get_next_address(ctx, &ext->addr) < 0) return -1;
    trace(LOG_CONTEXT, "cpu_enable_stepping_mode 0x%x", (int)ext->addr);
    if (context_read_mem(grp, ext->addr, ext->opcode, sizeof(BREAK_INST)) < 0) return -1;
    if (context_write_mem(grp, ext->addr, BREAK_INST, sizeof(BREAK_INST)) < 0) return -1;
    ext->sw_stepping = 1;
    run_ctrl_lock();
    return 0;
}

static int disable_sw_stepping_mode(Context * ctx) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionARM * ext = EXT(grp);
    trace(LOG_CONTEXT, "cpu_disable_stepping_mode");
    if (ext->sw_stepping) {
        run_ctrl_unlock();
        ext->sw_stepping = 0;
        if (grp->exited) return 0;
        return context_write_mem(grp, ext->addr, ext->opcode, sizeof(BREAK_INST));
    }
    return 0;
}

int cpu_enable_stepping_mode(Context * ctx, uint32_t * is_cont) {
    *is_cont = 1;
#if ENABLE_HardwareBreakpoints
    {
        ContextExtensionARM * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
        if (get_bp_info(ctx) < 0) return -1;
        if (bps->bp_cnt > 0) return enable_hw_stepping_mode(ctx, bps->arch > 2 ? 2 : 1);
    }
#endif /* ENABLE_HardwareBreakpoints */
    return enable_sw_stepping_mode(ctx);
}

int cpu_disable_stepping_mode(Context * ctx) {
#if ENABLE_HardwareBreakpoints
    {
        ContextExtensionARM * bps = EXT(context_get_group(ctx, CONTEXT_GROUP_BREAKPOINT));
        if (bps->bp_cnt > 0) return disable_hw_stepping_mode(ctx);
    }
#endif /* ENABLE_HardwareBreakpoints */
    return disable_sw_stepping_mode(ctx);
}

static RegisterDefinition * alloc_reg(void) {
    RegisterDefinition * r = regs_index + regs_cnt++;
    assert(regs_cnt <= regs_max);
    r->dwarf_id = -1;
    r->eh_frame_id = -1;
    r->big_endian = big_endian_host();
    return r;
}

static void ini_reg_defs(void) {
    int i;
    RegisterDefinition * d;
    regs_cnt = 0;
    regs_max = 800;
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(RegisterDefinition) * regs_max);
    for (d = regs_def; d->name != NULL; d++) {
        RegisterDefinition * r = alloc_reg();
        assert(d->parent == NULL);
        *r = *d;
        if (r->offset == offsetof(REG_SET, REG_FP)) {
            r->role = "FP";
        }
        else if (r->offset == offsetof(REG_SET, REG_SP)) {
            r->role = "SP";
        }
        else if (r->offset == offsetof(REG_SET, REG_PC)) {
            r->role = "PC";
            pc_def = r;
        }
        else if (r->offset == REG_OFFSET(user.regs.uregs[14])) {
            r->role = "LR";
            lr_def = r;
        }
        else if (r->offset == offsetof(REG_SET, REG_CPSR)) {
            cpsr_def = r;
        }
        if (strcmp(r->name, "vfp") == 0) {
            RegisterDefinition * x = NULL;
            for (i = 0; i < 32; i++) {
                char nm[32];
                x = alloc_reg();
                snprintf(nm, sizeof(nm), "d%d", i);
                x->name = loc_strdup(nm);
                x->offset = REG_OFFSET(fp.fpregs[i]);
                x->size = 8;
                x->dwarf_id = 256 + i;
                x->eh_frame_id = 256 + i;
                x->parent = r;
            }
            x = alloc_reg();
            x->name = "fpscr";
            x->offset = REG_OFFSET(fp.fpscr);
            x->size = 4;
            x->parent = r;
        }
    }
}

void ini_cpudefs_mdep(void) {
    ini_reg_defs();
    context_extension_offset = context_extension(sizeof(ContextExtensionARM));
}

#endif
