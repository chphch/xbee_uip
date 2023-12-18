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
#include "dtls_client.h"
#include "timer.h"
#include "pt.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#include <stdlib.h>
#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"

#define SERVER_NAME	"localhost"
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define RX_BUF_SIZE	4096

#define MESSAGE		"Etho this"

static uint8_t *rx_buf = NULL;
static size_t rx_buf_size = RX_BUF_SIZE;
static size_t rx_left = 0;

static struct dtls_client_state s;

int network_connected = 0;

/*---------------------------------------------------------------------------*/
static int dtls_client_send(void *ctx, const unsigned char *buf, size_t len)
{
	uip_send(buf, len);
	return len;
}

static int dtls_client_recv(void *ctx, unsigned char *buf, size_t len)
{
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
	}
	else
		return MBEDTLS_ERR_SSL_WANT_READ;
}

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
	((void) ctx);
    ((void) level);

    mbedtls_printf("%s:%04d: %s", file, line, str );
}

/*---------------------------------------------------------------------------*/
static
PT_THREAD(handle_dtls_client(void))
{
    static int ret = 0, len;
    static uint32_t flags;
	static unsigned char buf[1024];
    static const char *pers = "dtls_client";
	static int retry_left = 5;

    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_ssl_context ssl;
    static mbedtls_ssl_config conf;
    static mbedtls_x509_crt cacert;
	static mbedtls_timing_delay_context timer;

    PT_BEGIN(&s.pt);

#if defined(MBEDTLS_DEBUG_C)
	//mbedtls_debug_set_threshold(3);
#endif

 /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 0. Load certificates
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    mbedtls_printf( "  . Connecting to udp/%s/%d...", SERVER_NAME,
			UDP_SERVER_PORT );
    fflush( stdout );

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup stuff
     */
    mbedtls_printf( "  . Setting up the DTLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, NULL,
                         dtls_client_send, dtls_client_recv,
						 NULL );

    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );
    mbedtls_printf( " ok\n" );

	PT_WAIT_UNTIL(&s.pt, network_connected);

    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );

    do {
		ret = mbedtls_ssl_handshake( &ssl );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PT_YIELD_UNTIL(&s.pt, uip_newdata());
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
     * handshake would not succeed if the peer's cert is bad.  Even if we used
     * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        mbedtls_printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
    }
    else
        mbedtls_printf( " ok\n" );

    /*
     * 6. Write the echo request
     */
send_request:
    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );

    len = sizeof( MESSAGE ) - 1;

    do {
		ret = mbedtls_ssl_write( &ssl, (unsigned char *) MESSAGE, len );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PT_YIELD_UNTIL(&s.pt, uip_newdata());
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    mbedtls_printf( " %d bytes written\n\n%s\n\n", len, MESSAGE );

    /*
     * 7. Read the echo response
     */
    mbedtls_printf( "  < Read from server:" );
    fflush( stdout );

    len = sizeof( buf ) - 1;
    memset( buf, 0, sizeof( buf ) );

    do {
		ret = mbedtls_ssl_read( &ssl, buf, len );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PT_YIELD_UNTIL(&s.pt, uip_newdata());
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret <= 0 )
    {
        switch( ret )
        {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                mbedtls_printf( " timeout\n\n" );
                if( retry_left-- > 0 )
                    goto send_request;
                goto exit;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                mbedtls_printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n\n", -ret );
                goto exit;
        }
    }

    len = ret;
    mbedtls_printf( " %d bytes read\n\n%s\n\n", len, buf );

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    mbedtls_printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    mbedtls_printf( " done\n" );

    /*
     * 9. Final clean-ups and exit
     */
exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_x509_crt_free( &cacert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

	PT_WAIT_UNTIL(&s.pt, 0);

    PT_END(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
dtls_client_init(void)
{
  uip_ipaddr_t addr;
  
  uip_ip6addr(addr, 0xfe80, 0, 0, 0, 0x0213, 0xa200, 0x421c, 0x4aea);

  s.conn = uip_udp_new(&addr, HTONS(UDP_SERVER_PORT));
  if (s.conn)
	  uip_udp_bind(s.conn, HTONS(UDP_CLIENT_PORT));

  rx_buf = malloc(rx_buf_size);
  if (rx_buf == NULL) {
	  perror("malloc");
	  return;
  }

  PT_INIT(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
dtls_client_appcall(void)
{
  handle_dtls_client();
}
/*---------------------------------------------------------------------------*/
