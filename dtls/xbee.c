/*
 * Copyright (c) 2001, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 * $Id: tapdev.c,v 1.8 2006/06/07 08:39:58 adam Exp $
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <errno.h>
#include <termios.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>

#define XBEEDEV "/dev/ttyUSB0"

#include "uip.h"

#define SLIP_END	0300
#define SLIP_ESC	0333
#define SLIP_ESC_END	0334
#define SLIP_ESC_ESC	0335
#define XBEE_DATA_MAX	4096

static int xbee_fd;
static unsigned char xbee_data[XBEE_DATA_MAX];
static int xbee_data_len = 0;


/*---------------------------------------------------------------------------*/
static int open_port(const char *port_name, int baudrate)
{
	struct termios options;
	int fd;
	speed_t speed = baudrate;

	fd = open(port_name, O_RDWR | O_NOCTTY | O_NDELAY);
	if (fd < 0)
		return -1;

	if (tcgetattr(fd, &options) == -1)
		goto err;

	if (cfsetispeed(&options, speed) || cfsetospeed(&options, speed))
		goto err;

	options.c_cflag |= (CLOCAL | CREAD);
	/* 8 bit data */
	options.c_cflag &= ~CSIZE;
	options.c_cflag |= CS8;
	/* No Parity */
	options.c_cflag &= ~PARENB;
	options.c_cflag &= ~PARODD;
	options.c_iflag &= ~(INPCK | ISTRIP);
	/* 1 stop bit */
	options.c_cflag &= ~CSTOPB;
	/* No hw flow control */
	options.c_cflag &= ~CRTSCTS;
	/* No sw flow control */
	options.c_iflag &= ~(IXON | IXOFF | IXANY);
	/* Raw Input */
	options.c_iflag &= ~(BRKINT | ICRNL);
	options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	/* Raw Output */
	options.c_oflag &= ~OPOST;
	/* No wait time */
	options.c_cc[VMIN]  = 0;
	options.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSANOW, &options))
		goto err;

	return fd;

err:
	close(fd);
	return -1;
}

void
xbee_init(const char *dev_name)
{
  xbee_fd = open_port(dev_name, B9600);
  if(xbee_fd == -1) {
    perror("xbee: xbee_init: open");
    exit(1);
  }
}
/*---------------------------------------------------------------------------*/
unsigned int xbee_read(void)
{
	int start_idx, end_idx;
	fd_set fdset;
	struct timeval tv;
	int ret, i, len, esc = 0;
	unsigned char buf[XBEE_DATA_MAX], *ptr;
  
	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	FD_ZERO(&fdset);
	FD_SET(xbee_fd, &fdset);

	ret = select(xbee_fd + 1, &fdset, NULL, NULL, &tv);
	if(ret == 0) {
		return 0;
	}

	ret = read(xbee_fd, buf, XBEE_DATA_MAX);
	if(ret == -1) {
		perror("xbee_dev: xbee_read: read");
		return 0;
	}

	if ((xbee_data_len + ret) > XBEE_DATA_MAX) {
		printf("xbee_dev: buffer not available\n");
		return 0;
	}

	memcpy(&xbee_data[xbee_data_len], buf, ret);
	xbee_data_len += ret;

	ptr = memchr(&xbee_data[0], SLIP_END, xbee_data_len);
	if (!ptr)
		return 0;

	start_idx = ptr - &xbee_data[0];

	ptr = memchr(&xbee_data[start_idx + 1], SLIP_END, 
			xbee_data_len - start_idx - 1);
	if (!ptr)
		return 0;

	end_idx = ptr - &xbee_data[0];
	
	for (i = start_idx + 1, len = 0; i < end_idx; i++) {
		if (esc) {
			if (xbee_data[i] == SLIP_ESC_ESC)
				uip_buf[len++] = SLIP_ESC;
			else if (xbee_data[i] == SLIP_ESC_END)
				uip_buf[len++] = SLIP_END;
			esc = 0;
		}
		else if (xbee_data[i] == SLIP_ESC)
			esc = 1;
		else 
			uip_buf[len++] = xbee_data[i];
	}

	xbee_data_len -= (end_idx + 1);
	memmove(&xbee_data[0], &xbee_data[end_idx + 1], xbee_data_len);

	return len;
}

/*---------------------------------------------------------------------------*/
void
xbee_send(void)
{
  int i;
  unsigned char c;

  c = SLIP_END;
  write(xbee_fd, &c, 1);

  for (i = 0; i < uip_len; i++) {
	  c = uip_buf[i];
	  if (c == SLIP_END) {
		  c = SLIP_ESC;
		  write(xbee_fd, &c, 1);
		  c = SLIP_ESC_END;
	  }
	  else if (c == SLIP_ESC) {
		  c = SLIP_ESC;
		  write(xbee_fd, &c, 1);
		  c = SLIP_ESC_ESC;
	  }

	  write(xbee_fd, &c, 1);
  }

  c = SLIP_END;
  write(xbee_fd, &c, 1);
}
/*---------------------------------------------------------------------------*/
