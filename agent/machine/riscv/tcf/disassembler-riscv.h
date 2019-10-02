/*******************************************************************************
 * Copyright (c) 2019 Xilinx, Inc. and others.
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
 *     Xilinx - initial API and implementation
 *******************************************************************************/

#ifndef D_disassembler_riscv
#define D_disassembler_riscv

#include <tcf/config.h>

#include <tcf/services/disassembly.h>

extern DisassemblyResult * disassemble_riscv32(uint8_t * buf,
    ContextAddress addr, ContextAddress size, DisassemblerParams * params);

extern DisassemblyResult * disassemble_riscv64(uint8_t * buf,
    ContextAddress addr, ContextAddress size, DisassemblerParams * params);

extern DisassemblyResult * disassemble_riscv128(uint8_t * buf,
    ContextAddress addr, ContextAddress size, DisassemblerParams * params);

#endif /* D_disassembler_riscv */
