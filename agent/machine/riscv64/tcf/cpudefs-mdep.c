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

#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#if ENABLE_ContextMux
#include <tcf/framework/cpudefs-mdep-mux.h>
#endif
#include <tcf/cpudefs-mdep.h>

unsigned char BREAK_INST[] = {0x02, 0x90};

RegisterDefinition * regs_index;

static const RegisterDefinition rv_regs[] = {
    {.name="pc", .description="Program counter", .role="PC"},
    {.name="ra", .description="Return address", .role="RET"},
    {.name="sp", .description="Stack pointer", .role="SP"},
    {.name="gp", .description="Global pointer"},
    {.name="tp", .description="Thread pointer"},
    {.name="t0", .description="Temporary register"},
    {.name="t1", .description="Temporary register"},
    {.name="t2", .description="Temporary register"},
    {.name="s0", .description="Saved register"},
    {.name="s1", .description="Saved register"},
    {.name="a0", .description="Function argument / frame pointer"},
    {.name="a1", .description="Function argument / frame pointer"},
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

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return regs_index;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return 0;
}

#if ENABLE_ini_cpudefs_mdep
void ini_cpudefs_mdep(void) {
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(rv_regs));
    int i;
    for (i = 0; rv_regs[i].name != NULL; ++i) {
        RegisterDefinition * r = regs_index + i;
        *r = rv_regs[i];
        r->offset = i * 8;
        r->size = 8;
        r->dwarf_id = i;
        r->eh_frame_id = i;
  }
}
#endif

#endif /* ENABLE_DebugContext && !ENABLE_ContextProxy */
