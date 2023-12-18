# Copyright (c) 2001, Adam Dunkels.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote
#    products derived from this software without specific prior
#    written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This file is part of the uIP TCP/IP stack.
#
# $Id: Makefile,v 1.13 2006/06/11 21:55:03 adam Exp $
#

APP = server
#APP = client
TARGET = dtls_$(APP)

all: $(TARGET)

#CC     = gcc
#AR     = ar
CFLAGS = -Wall -g -I../uip -I. 
-include ../uip/Makefile.include

# vpath %.c ../mbedtls

# MBEDTLS_OBJS = ${subst .c,.o, ${subst ../mbedtls/,,${wildcard ../mbedtls/*.c}}}
OBJS = main.o xbee.o clock-arch.o $(TARGET).o db.o model.o

LIBS = -lsqlite3

ifeq ($(FDTLS),1)
CFLAGS += -I../tinydtls-uip-port -I../tinydtls-uip-port/uip-support
LIBS += ../tinydtls-uip-port/libtinydtls.a 
endif

CFLAGS += -fno-stack-protector
# CFLAGS += -DMBEDTLS_CONFIG_FILE='<mbedtls_config.h>'

$(TARGET): $(addprefix $(OBJECTDIR)/, $(OBJS)) uip.a
	$(CC) $(CFLAGS) $^ -o $@  $(LIBS)

clean:
	rm -fr *.o *~ *core $(TARGET) $(OBJECTDIR) *.a
