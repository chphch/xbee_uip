/*
 * Copyright (c) 2001, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Adam Dunkels.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 * $Id: main.c,v 1.16 2006/06/11 21:55:03 adam Exp $
 *
 */


#include <string.h>

#include "uip.h"
#include "uip_arp.h"
#include "xbee.h"

#include "timer.h"


/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
  int i;
  uip_ipaddr_t ipaddr;
  struct timer periodic_timer, arp_timer;
  extern int network_connected;

  if (argc != 2) {
	  printf("usage) %s {xbee device}\n", argv[0]);
	  return 0;
  }
  timer_set(&periodic_timer, CLOCK_SECOND / 2);
  timer_set(&arp_timer, CLOCK_SECOND * 10);
  
  xbee_init(argv[1]);
  uip_init();

#ifdef client
  /* Set IP address of this device */
  uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0213, 0xa200, 0x421c, 0x4af1);
  uip_sethostaddr(ipaddr);

  dtls_client_init();
#else
  /* Set IP address of this device */
  uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0213, 0xa200, 0x421c, 0x4af5);
  uip_sethostaddr(ipaddr);
  
  printf(
	"Server: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
	(ipaddr[0] & 0xff), (ipaddr[0] >> 8) & 0xff,
	(ipaddr[1] & 0xff), (ipaddr[1] >> 8) & 0xff,
	(ipaddr[2] & 0xff), (ipaddr[2] >> 8) & 0xff,
	(ipaddr[3] & 0xff), (ipaddr[3] >> 8) & 0xff,
	(ipaddr[4] & 0xff), (ipaddr[4] >> 8) & 0xff,
	(ipaddr[5] & 0xff), (ipaddr[5] >> 8) & 0xff,
	(ipaddr[6] & 0xff), (ipaddr[6] >> 8) & 0xff,
	(ipaddr[7] & 0xff), (ipaddr[7] >> 8) & 0xff
  );
  xbee_read();
  

  dtls_server_init();
#endif
  
  while(1) {
    uip_len = xbee_read();
    if(uip_len > 0) {

		// Receives an input from client

#if 0
		printf("rcv uip_len = %d\n", uip_len);
#endif
		network_connected = 1;
		uip_input(); // Process an incoming packet. 
		// This will let PT_YIELD_UNTIL(&s.pt, network_connected); in handle_dtls_server thread in server.c go on

		/* If the above function invocation resulted in data that
			should be sent out on the network, the global variable
			uip_len is set to a value > 0. */
		if(uip_len > 0){
			xbee_send();
		}

	} else if(timer_expired(&periodic_timer)) {
		timer_reset(&periodic_timer);
		for(i = 0; i < UIP_CONNS; i++) {
			uip_periodic(i);
			/* If the above function invocation resulted in data that
			 should be sent out on the network, the global variable
			   uip_len is set to a value > 0. */
			if(uip_len > 0)
			  xbee_send();
		}

#if UIP_UDP
		for(i = 0; i < UIP_UDP_CONNS; i++) {
			uip_udp_periodic(i);
			/* If the above function invocation resulted in data that
			   should be sent out on the network, the global variable
			 uip_len is set to a value > 0. */
			if(uip_len > 0)
			  xbee_send();
		}
#endif /* UIP_UDP */
      
		/* Call the ARP timer function every 10 seconds. */
		if(timer_expired(&arp_timer)) {
			timer_reset(&arp_timer);
			uip_arp_timer();
		}
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
