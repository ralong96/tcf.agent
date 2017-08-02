/*******************************************************************************
 * Copyright (c) 2017 Xilinx, Inc. and others.
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

#ifndef D_cpu_regs_gdb_a64
#define D_cpu_regs_gdb_a64

#include <tcf/config.h>

static const char * cpu_regs_gdb_a64 =
"<architecture>aarch64</architecture>\n"
"<feature name='org.gnu.gdb.aarch64.core'>\n"
"  <reg name='x0' bitsize='64' id='0' />\n"
"  <reg name='x1' bitsize='64' id='1' />\n"
"  <reg name='x2' bitsize='64' id='2' />\n"
"  <reg name='x3' bitsize='64' id='3' />\n"
"  <reg name='x4' bitsize='64' id='4' />\n"
"  <reg name='x5' bitsize='64' id='5' />\n"
"  <reg name='x6' bitsize='64' id='6' />\n"
"  <reg name='x7' bitsize='64' id='7' />\n"
"  <reg name='x8' bitsize='64' id='8' />\n"
"  <reg name='x9' bitsize='64' id='9' />\n"
"  <reg name='x10' bitsize='64' id='10' />\n"
"  <reg name='x11' bitsize='64' id='11' />\n"
"  <reg name='x12' bitsize='64' id='12' />\n"
"  <reg name='x13' bitsize='64' id='13' />\n"
"  <reg name='x14' bitsize='64' id='14' />\n"
"  <reg name='x15' bitsize='64' id='15' />\n"
"  <reg name='x16' bitsize='64' id='16' />\n"
"  <reg name='x17' bitsize='64' id='17' />\n"
"  <reg name='x18' bitsize='64' id='18' />\n"
"  <reg name='x19' bitsize='64' id='19' />\n"
"  <reg name='x20' bitsize='64' id='20' />\n"
"  <reg name='x21' bitsize='64' id='21' />\n"
"  <reg name='x22' bitsize='64' id='22' />\n"
"  <reg name='x23' bitsize='64' id='23' />\n"
"  <reg name='x24' bitsize='64' id='24' />\n"
"  <reg name='x25' bitsize='64' id='25' />\n"
"  <reg name='x26' bitsize='64' id='26' />\n"
"  <reg name='x27' bitsize='64' id='27' />\n"
"  <reg name='x28' bitsize='64' id='28' />\n"
"  <reg name='x29' bitsize='64' id='29' />\n"
"  <reg name='x30' bitsize='64' id='30' />\n"
"  <reg name='sp' bitsize='64' type='data_ptr' id='31' />\n"
"  <reg name='pc' bitsize='64' type='code_ptr' id='33' />\n"
"  <flags id='cpsr_flags' size='4'>\n"
"    <field name='SP'  start='0'  end='0' />\n"
"    <field name=''    start='1'  end='1' />\n"
"    <field name='EL'  start='2'  end='3' />\n"
"    <field name='nRW' start='4'  end='4' />\n"
"    <field name=''    start='5'  end='5' />\n"
"    <field name='F'   start='6'  end='6' />\n"
"    <field name='I'   start='7'  end='7' />\n"
"    <field name='A'   start='8'  end='8' />\n"
"    <field name='D'   start='9'  end='9' />\n"
"    <field name='IL'  start='20' end='20' />\n"
"    <field name='SS'  start='21' end='21' />\n"
"    <field name='V'   start='28' end='28' />\n"
"    <field name='C'   start='29' end='29' />\n"
"    <field name='Z'   start='30' end='30' />\n"
"    <field name='N'   start='31' end='31' />\n"
"  </flags>\n"
"  <reg name='cpsr' bitsize='32' type='cpsr_flags' />\n"
"</feature>\n";

#endif /* D_cpu_regs_gdb_a64 */
