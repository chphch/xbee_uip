/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
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
 * This file is part of the uIP TCP/IP stack
 *
 * @(#)$Id: dhcpc.c,v 1.2 2006/06/11 21:46:37 adam Exp $
 */

#include <stdio.h>
#include <string.h>

#include "uip.h"
#include "dtls_server.h"
#include "timer.h"
#include "pt.h"
#include "meter_data.h"
#include "db.h"


#include <stdio.h>

#include <stdlib.h>
#include <string.h>


#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

// #define USE_FDTLS 1

#define DEBUG_LEVEL 0

#define RX_BUF_SIZE	4096

static uint8_t *rx_buf = NULL;
static size_t rx_buf_size = RX_BUF_SIZE;
static size_t rx_left = 0;
static struct dtls_server_state s;
static uint8_t client_ip[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
	0x02, 0x13, 0xa2, 0x00, 0x42, 0x1c, 0x4a, 0xe0};

#define UDPBUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

#ifdef USE_FDTLS
#include "tinydtls.h"
// static session_t src_session;
static dtls_context_t *dtls_context;


int handshake_complete = 0;
struct timer handshake_timer;
#endif /* USE_FDTLS */
int network_connected = 0;
static int _hs = 0;

// #define RUN_MODEL 0

#ifdef RUN_MODEL
#include "model.h"
#define FDATK_NCLI 10 // CHANGE ME:number of clients
typedef struct {
  uint32_t data[FDATK_NCOL];
} FDATK_DATA_PERCLI;

typedef struct {
  FDATK_DATA_PERCLI data[FDATK_NCLI];
  uip_ipaddr_t sender[FDATK_NCLI];
  uint16_t n_registered_cli;
  bool has_new_data[FDATK_NCLI];
} FDATK_DATA_INPUT;
#endif /* RUN_MODEL */

sqlite3* db;

/*---------------------------------------------------------------------------*/

static int server_send(const unsigned char *buf, size_t len)
{
	uip_send(buf, len);
	return len;
}

static int server_recv(unsigned char *buf, size_t len)
{
  memset(buf, 0, len);
	if (rx_left || uip_newdata()) {
		if (rx_left == 0) {
			memcpy(rx_buf, uip_appdata, uip_len);
			rx_left = uip_len;
			uip_flags = 0;
		}

		if (rx_left > len) {
			rx_left -= len;

			memcpy(buf, rx_buf, len);
			memmove(rx_buf, rx_buf + len, rx_left);

			return len;
		}
		else {
			len = rx_left;
			rx_left = 0;
			memcpy(buf, rx_buf, len);
			return len;
		}
	} else {
        return -1;
    }
}


#ifdef USE_FDTLS

static int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8_t *data, size_t len) {
  size_t i;
  printf("read_from_peer: %s(%u)\n", data, len);
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  printf("\n");
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8_t *data, size_t len) {
  
  printf("send_to_peer: %s(%u)\n", data, len);
  return server_send(data, len);
}

static int
dtls_handle_read(struct dtls_context_t *ctx) {
  
  static session_t session;
  static uint8_t buf[RX_BUF_SIZE];
  int len;

  if(uip_newdata()) {
    uip_ipaddr_copy(&session.addr, UDPBUF->srcipaddr);
    session.port = UDPBUF->srcport;

    // len = uip_datalen();

    // if (len > sizeof(buf)) {
    //   // dtls_warn("packet is too large");
    //   return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    // }

    len = server_recv(buf, RX_BUF_SIZE);
  }
  return dtls_handle_message(ctx, &session, buf, len);
}

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 16,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 }
  };

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) {
    int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
        if (result_length < psk[i].key_length) {
          return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }

        memcpy(result, psk[i].key, psk[i].key_length);
        return psk[i].key_length;
      }
    }
  }
  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif /* DTLS_PSK */

static int
dtls_complete(struct dtls_context_t *ctx, session_t *session, dtls_alert_level_t level, unsigned short code){

  if(code == DTLS_EVENT_CONNECTED) {
    handshake_complete = 1;
    printf("handshake_complete!\n");
    //struct etimer et;
    timer_set(&handshake_timer,CLOCK_SECOND*5);

    //buflen = sizeof(buf);
    //dtls_write(ctx, session, (uint8 *)buf, buflen);
    //rtimer_count = rtimer_arch_now();
    //printf("send packet\n");
  }
  return 0;
}
# endif /* USE_FDTLS */

int received_from_client(){
  return uip_newdata() && UDPBUF->proto == 17;
}

/*---------------------------------------------------------------------------*/
int data_idx = 0;
long initial_timestamp = 0;
static
PT_THREAD(handle_dtls_server(void))
{
    // static int ret = 0, len;
    // static unsigned char buf[1024];
    // static const char *pers = "dtls_server";

    PT_BEGIN(&s.pt);

    /*
     * 2. Setup the "listening" UDP socket
     */
    printf( "  . Bind on udp/*/%d ...", UDP_SERVER_PORT);

	  PT_YIELD_UNTIL(&s.pt, network_connected);
    printf( "  . New connection\n");
    

    /*
      // printf("UDPBUF srcipaddr\n");
    // for (int i = 0; i < 8; i++) {
    //     printf("%02X%02X:", (uint8_t) (UDPBUF->srcipaddr[i] & 0xff), (uint8_t) (UDPBUF->srcipaddr[i] >> 8));
    // }
    // printf("\n");

    // printf("UDPBUF destipaddr\n");
    // for (int i = 0; i < 8; i++) {
    //     printf("%02X%02X:", (uint8_t) (UDPBUF->destipaddr[i] & 0xff), (uint8_t) (UDPBUF->destipaddr[i] >> 8));
    // }
    // printf("\n");
    // printf("UDPBUF proto %d\n", UDPBUF->proto); // uip.h UIP_PROTO_ICMP6 58, UIP_PROTO_UDP 17


    // for (int i = 0; i < 8; i++) {
    //     printf("%02X%02X:", (uint8_t) (s.conn->ripaddr[i] & 0xff), (uint8_t) (s.conn->ripaddr[i] >> 8));
    // }
    // printf("\n");

    // printf(" To \n");
    // for (int i = 0; i < 8; i++) {
    //     printf("%02X%02X:", (uint8_t) (uip_hostaddr[i] & 0xff), (uint8_t) (uip_hostaddr[i] >> 8));
    // }
    // printf("\n");
    */

    // Wait for syn
    printf("Wait for syn\n");
    fflush(stdout);
    
    uint8_t buf[RX_BUF_SIZE];
    while(1){
      if (received_from_client()){
        server_recv(buf, RX_BUF_SIZE);
        if (strcmp(buf, "syn") == 0 && _hs==0){
          printf("syn received\n");
          if(server_send("syn ack\0", 8) == 8){
            printf("syn ack sent\n");
            _hs++;
          }
        } else if (strcmp(buf, "ack") == 0 && _hs==1){
          printf("ack received\n");
          _hs++;
          break;
        }
      }
      PT_YIELD_UNTIL(&s.pt, uip_newdata());
    }

    #ifdef USE_FDTLS
    while(1){
        PT_YIELD_UNTIL(&s.pt, uip_newdata());
        if (UDPBUF->proto == 17){
            // UDP INPUT
            dtls_handle_read(dtls_context);
            if(handshake_complete == 1 ) {
              do{} while(!timer_expired(&handshake_timer));
              printf("handshake_complete!\n");
            }
        }
    }
    #endif /* USE_FDTLS */

    /* Receive meter data*/
    printf("Wait for meter data..\n");
    initial_timestamp = clock_time();
    while(1){
      if (received_from_client()){
        int len = server_recv(buf, RX_BUF_SIZE);
        
        if (len > 0){
          // printf("Received: %s(%d)\n", buf, len);
          if (buf[0] == 'T'){
            meter_information_t meter_information;

            // Parse. Format: sprintf(msg, "T:%05d|D:%s|V:%s|I:%s", meter_information.timestamp, meter_information.id, meter_information.V, meter_information.I);
            char *token = strtok(buf, "|");
            int i = 0;
            while (token != NULL) {
              token = token + 2;
              switch (i){
                case 0:
                  meter_information.timestamp = atoi(token);
                  break;
                case 1:
                  strcpy(meter_information.id, token);
                  // meter_information.id = atoi(token);
                  break;
                case 2:
                  strcpy(meter_information.V, token);
                  // meter_information.V = atoi(token);
                  break;
                case 3:
                  strcpy(meter_information.I, token);
                  // meter_information.I = atoi(token);
                  break;
                default:
                  break;
              }
              token = strtok(NULL, "|");
              i++;
            }
          
            // printf("T:%d|D:%s|V:%s|I:%s\n", meter_information.timestamp, meter_information.id, meter_information.V, meter_information.I);
            
            long received_timestamp = clock_time();
            
            printf("T:%ld|D:%s|V:%s|I:%s\n", received_timestamp-initial_timestamp, meter_information.id, meter_information.V, meter_information.I);

            // Insert to db
            insert_meter_information(db, data_idx++, meter_information.id, meter_information.V, meter_information.I);
          } 

          // if first 3 characters are "F, "
          if (buf[0] == 'F'){
            // Flooding attack detection
            long received_timestamp = clock_time();
            
            // Parse. Format: sprintf(msg, "F, D:%s|A:%d", meter_information.id, 1);

            char moteid[20];
            int attack;

            sscanf(buf, "F, D:%19[^|]|A:%d", moteid, &attack);

            char attack_description[20];
            if (attack == 1){
              strcpy(attack_description, "Under attack");
            } else {
              strcpy(attack_description, "Normal");
            }

            insert_attack_information(db, "Gateway", attack_description);
          }

        }
        // if starts with t
      }
      PT_YIELD_UNTIL(&s.pt, uip_newdata());
    }

	  PT_WAIT_UNTIL(&s.pt, 0);

    PT_END(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
dtls_server_init(void)
{

    db = create_db();

    uip_ipaddr_t* client_ip_addr = (uip_ipaddr_t *) client_ip;
    s.conn = uip_udp_new(client_ip_addr, HTONS(UDP_CLIENT_PORT));
    if (s.conn)
        uip_udp_bind(s.conn, HTONS(UDP_SERVER_PORT));

    rx_buf = malloc(rx_buf_size);
    if (rx_buf == NULL) {
      perror("malloc");
      return;
    }

#ifdef USE_FDTLS
    dtls_init();

    static dtls_handler_t cb = {
        .write = send_to_peer,
        .read  = read_from_peer,
        .event = dtls_complete,
    #ifdef DTLS_PSK
        .get_psk_info = get_psk_info,
    #endif /* DTLS_PSK */
    // #ifdef DTLS_ECC
    //     .get_ecdsa_key = get_ecdsa_key,
    //     .verify_ecdsa_key = verify_ecdsa_key
    // #endif /* DTLS_ECC */
    };

      

    dtls_context = dtls_new_context(&s.conn);
    if (dtls_context)
        dtls_set_handler(dtls_context, &cb);
#endif /* USE_FDTLS */

    PT_INIT(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
dtls_server_appcall(void)
{
  handle_dtls_server();
}
/*---------------------------------------------------------------------------*/
