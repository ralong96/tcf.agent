/*******************************************************************************
* Copyright (c) 2019.
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* and Eclipse Distribution License v1.0 which accompany this distribution.
* The Eclipse Public License is available at
* http://www.eclipse.org/legal/epl-v10.html
* and the Eclipse Distribution License is available at
* http://www.eclipse.org/org/documents/edl-v10.php.
* You may elect to redistribute this code under either of these licenses.
*
*******************************************************************************/
#include <tcf/config.h>

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <assert.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#if ENABLE_ContextMux
#include <tcf/framework/cpudefs-mdep-mux.h>
#endif
#include <tcf/disassembler-riscv64.h>
#include <tcf/stack-crawl-riscv64.h>
#include <tcf/cpudefs-mdep.h>

unsigned char BREAK_INST[] = {0x02, 0x90};
RegisterDefinition * regs_index;

static RegisterDefinition * reg_pc;
static unsigned regs_cnt;
static unsigned regs_max;

#define REG_OFFSET(name) offsetof(REG_SET, name)

static const RegisterDefinition rv_regs[] = {
    {.name="zero", .description="Zero register", .offset=REG_OFFSET(other), .no_write = 1},
    {.name="ra", .description="Return address", .role="RET"},
    {.name="sp", .description="Stack pointer", .role="SP"},
    {.name="gp", .description="Global pointer"},
    {.name="tp", .description="Thread pointer"},
    {.name="t0", .description="Temporary register"},
    {.name="t1", .description="Temporary register"},
    {.name="t2", .description="Temporary register"},
    {.name="s0", .description="Saved register / frame pointer"},
    {.name="s1", .description="Saved register"},
    {.name="a0", .description="Function argument / return value"},
    {.name="a1", .description="Function argument"},
    {.name="a2", .description="Function argument"},
    {.name="a3", .description="Function argument"},
    {.name="a4", .description="Function argument"},
    {.name="a5", .description="Function argument"},
    {.name="a6", .description="Function argument"},
    {.name="a7", .description="Function argument"},
    {.name="s2", .description="Saved register"},
    {.name="s3", .description="Saved register"},
    {.name="s4", .description="Saved register"},
    {.name="s5", .description="Saved register"},
    {.name="s6", .description="Saved register"},
    {.name="s7", .description="Saved register"},
    {.name="s8", .description="Saved register"},
    {.name="s9", .description="Saved register"},
    {.name="s10", .description="Saved register"},
    {.name="s11", .description="Saved register"},
    {.name="t3", .description="Temporary register"},
    {.name="t4", .description="Temporary register"},
    {.name="t5", .description="Temporary register"},
    {.name="t6", .description="Temporary register"},
    {NULL}
};

static RegisterDefinition * alloc_reg(void) {
    RegisterDefinition * r = regs_index + regs_cnt++;
    assert(regs_cnt <= regs_max);
    return r;
}

static RegisterDefinition * alloc_spr(const char * name, size_t offset, size_t size, int16_t id, const char * desc) {
    RegisterDefinition * reg = alloc_reg();
    reg->name = loc_strdup(name);
    reg->description = loc_strdup(desc);
    reg->dwarf_id = id;
    reg->eh_frame_id = id;
    reg->offset = offset;
    reg->size = size;
    return reg;
}

int mdep_get_other_regs(pid_t pid, REG_SET * data, size_t data_offs, size_t data_size,
        size_t * done_offs, size_t * done_size) {
    assert(data_offs >= REG_OFFSET(other));
    assert(data_offs + data_size <= REG_OFFSET(other) + sizeof(data->other));
    (void)pid;
    data->other = 0;
    *done_offs = REG_OFFSET(other);
    *done_size = sizeof(data->other);
    return 0;
}

int mdep_set_other_regs(pid_t pid, REG_SET * data, size_t data_offs, size_t data_size,
        size_t * done_offs, size_t * done_size) {
    assert(data_offs >= REG_OFFSET(other));
    assert(data_offs + data_size <= REG_OFFSET(other) + sizeof(data->other));
    (void)pid;
    *done_offs = REG_OFFSET(other);
    *done_size = sizeof(data->other);
    return 0;
}

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return reg_pc;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return crawl_stack_frame_riscv64(frame, down);
}

#if defined(ENABLE_add_cpudefs_disassembler) && ENABLE_add_cpudefs_disassembler
void add_cpudefs_disassembler(Context * cpu_ctx) {
    add_disassembler(cpu_ctx, "Riscv64", disassemble_riscv64);
}
#endif

void ini_cpudefs_mdep(void) {
    int i;
    regs_cnt = 0;
    regs_max = 128;
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(RegisterDefinition) * regs_max);

    for (i = 0; rv_regs[i].name != NULL; ++i) {
        RegisterDefinition * r = alloc_reg();
        *r = rv_regs[i];
        r->size = 8;
        r->dwarf_id = i;
        r->eh_frame_id = i;
        if (r->offset == 0) r->offset = i * 8;
    }
    reg_pc = alloc_spr("pc", REG_OFFSET(gp.pc), 8, -1, "Program counter");
    reg_pc->role = "PC";
}

#endif /* ENABLE_DebugContext && !ENABLE_ContextProxy */
