/*******************************************************************************
 * Copyright (c) 2014 Stanislav Yakovlev.
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
 *     Stanislav Yakovlev - initial API and implementation
 *******************************************************************************/

#include <stdio.h>
#include <tcf/config.h>
#include <machine/powerpc/tcf/disassembler-powerpc.h>

static char buf[128];
static size_t buf_pos = 0;

static void add_char(char ch) {
    if (buf_pos >= sizeof(buf) - 1) return;
    buf[buf_pos++] = ch;
    if (ch == ' ') while (buf_pos < 8) buf[buf_pos++] = ch;
}

static void add_str(const char * s) {
    while (*s) add_char(*s++);
}

static void add_dec_uint8(uint8_t n) {
    char buf[32];

    snprintf(buf, sizeof(buf), "%u", (unsigned int)n);
    add_str(buf);
}

static void add_dec_int16(int16_t n) {
    char buf[32];

    snprintf(buf, sizeof(buf), "%d", (int)n);
    add_str(buf);
}

static void add_hex_uint16(uint16_t n) {
    char buf[32];

    snprintf(buf, sizeof(buf), "0x%.4x", (unsigned int)n);
    add_str(buf);
}

DisassemblyResult * disassemble_powerpc(uint8_t * code,
        ContextAddress addr, ContextAddress size, DisassemblerParams * params) {
    static DisassemblyResult dr;
    uint32_t instr;

    if (size < 4) return NULL;
    memset(&dr, 0, sizeof(dr));
    dr.size = 4;
    buf_pos = 0;

    instr = code[0];
    instr <<= 8;
    instr |= code[1];
    instr <<= 8;
    instr |= code[2];
    instr <<= 8;
    instr |= code[3];

    snprintf(buf, sizeof(buf), ".word 0x%08x", instr);

    dr.text = buf;
    return &dr;
}
