#!/bin/sh
#*******************************************************************************
# Copyright (c) 2011, 2013 Wind River Systems, Inc. and others.
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License v1.0
# and Eclipse Distribution License v1.0 which accompany this distribution.
# The Eclipse Public License is available at
# http://www.eclipse.org/legal/epl-v10.html
# and the Eclipse Distribution License is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
# You may elect to redistribute this code under either of these licenses.
#
# Contributors:
#     Wind River Systems - initial API and implementation
#*******************************************************************************

TCF_MACHINE=`uname -m`
case $TCF_MACHINE in
  armv6l)
    TCF_MACHINE=arm
    ;;
  armv7l)
    TCF_MACHINE=arm
    ;;
  ppc64)
    TCF_MACHINE=powerpc
    ;;
  aarch64)
    TCF_MACHINE=a64
    ;;
esac

[ -d gcc-debug ] || mkdir gcc-debug
cd gcc-debug
[ -f Makefile ] || cmake -DTCF_MACHINE=$TCF_MACHINE -DCMAKE_BUILD_TYPE=Debug -G "Unix Makefiles" ../..
make $*
