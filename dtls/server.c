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
#include <unistd.h>

#include "uip.h"
#include "dtls_server.h"
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
#include "mbedtls/ssl_cookie.h"
#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define READ_TIMEOUT_MS 10000   /* 5 seconds */
#define DEBUG_LEVEL 0

#define RX_BUF_SIZE	4096
#define WINDOW_SIZE 60
#define FEATURE_SIZE 14
#define ERROR_BUF_SIZE 100

static uint8_t *rx_buf = NULL;
static size_t rx_buf_size = RX_BUF_SIZE;
static size_t rx_left = 0;
static struct dtls_server_state s;
static uint8_t client_ip[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
	0x02, 0x13, 0xa2, 0x00, 0x41, 0xa5, 0x9a, 0x62};

int network_connected = 0;

/*---------------------------------------------------------------------------*/
static int dtls_server_send(void *ctx, const unsigned char *buf, size_t len)
{
	uip_send(buf, len);
	return len;
}

static int dtls_server_recv(void *ctx, unsigned char *buf, size_t len)
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
PT_THREAD(handle_dtls_server(void))
{
    static int ret = 0, len;
    static unsigned char buf[16384];
    static char error_buf[ERROR_BUF_SIZE];
    static char curl_command_buf[16384];
    static const char *pers = "dtls_server";
    static mbedtls_ssl_cookie_ctx cookie_ctx;
    static size_t total_bytes_sent = 0;

    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_ssl_context ssl;
    static mbedtls_ssl_config conf;
    static mbedtls_x509_crt srvcert;
    static mbedtls_pk_context pkey;
    static mbedtls_timing_delay_context timer;
#if defined(MBEDTLS_SSL_CACHE_C)
    static mbedtls_ssl_cache_context cache;
#endif

    static clock_time_t start_time;
    static size_t num_received = 0;

    PT_BEGIN(&s.pt);
    start_time = clock_time();

#if defined(MBEDTLS_DEBUG_C)
	//mbedtls_debug_set_threshold(3);
#endif

init:

 /*
     * 0. Initialize the RNG and the session data
     */
	mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init( &conf );
    mbedtls_ssl_cookie_init( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    /*
     * 1. Load the certificates and private RSA key
     */
    printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                          mbedtls_test_srv_crt_len );
    if( ret != 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 2. Setup the "listening" UDP socket
     */
    printf( "  . Bind on udp/*/5678 ..." );
    fflush( stdout );
    printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    printf( "  . Setting up the DTLS data..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
   if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_cookie_setup( &cookie_ctx,
                                  mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_dtls_cookies( &conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                               &cookie_ctx );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );

    printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        mbedtls_strerror( ret, error_buf, ERROR_BUF_SIZE );
        printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */

	PT_WAIT_UNTIL(&s.pt, network_connected);


    /* For HelloVerifyRequest cookies */
    if( ( ret = mbedtls_ssl_set_client_transport_id( &ssl,
                    client_ip, 16 ) ) != 0 )
    {
        printf( " failed\n  ! "
                "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, NULL,
                         dtls_server_send, dtls_server_recv, NULL );

    printf( " ok\n" );

    /*
     * 5. Handshake
     */
    printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );

    do {
		ret = mbedtls_ssl_handshake( &ssl );
        mbedtls_strerror( ret, error_buf, 100 );
        printf( "Handshake error: %d - %s\n\n", ret, error_buf );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PT_YIELD_UNTIL(&s.pt, uip_newdata());
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        printf( " hello verification requested\n" );
        ret = 0;
        goto reset;
    }
    else if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
        goto reset;
    }

    printf( " ok\n" );

read:
    /*
     * 6. Read the echo Request
     */
    printf( "  < Read from client:" );
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
                printf( " timeout\n\n" );
                goto reset;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                printf( " mbedtls_ssl_read returned -0x%x\n\n", -ret );
                goto reset;
        }
    }
    int elapsed_secs = (clock_time() - start_time) / 1000;
    printf( " num_received: %u, elapsed time: %ds\n", ++num_received, elapsed_secs);

    len = ret;
    printf( " %d bytes read\n first value: %g, last value: %g\n",
        len, ((float*) buf)[0], ((float*) buf)[(WINDOW_SIZE * FEATURE_SIZE + 1) - 1] );

    char *ptr_str = curl_command_buf;
    ptr_str += sprintf(ptr_str, "/usr/bin/curl -X POST -d ");
    for (int i = 0; i < (WINDOW_SIZE * FEATURE_SIZE + 1); i++)
        ptr_str += sprintf(ptr_str, "%f,", ((float*) buf)[i]);
    ptr_str[-1] = ' ';
    ptr_str += sprintf(ptr_str, "147.46.219.67:23456 &> /dev/null\n");
    system(curl_command_buf);

    /*
     * 7. Write the 200 Response
     */
    printf( "  > Write to client:" );
    fflush( stdout );

    do ret = mbedtls_ssl_write( &ssl, (const unsigned char *) "SUCCESS", 7 );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    total_bytes_sent += len;
    printf( " %d bytes written, total_bytes_sent: %d\n", len, total_bytes_sent);

	PT_YIELD(&s.pt);

    goto read;

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do {
        ret = mbedtls_ssl_close_notify( &ssl );
        mbedtls_strerror( ret, error_buf, ERROR_BUF_SIZE );
        printf( "Close notify error: %d - %s\n\n", ret, error_buf );
    }
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    printf( " done\n" );

    goto reset;

    /*
     * Final clean-ups and exit
     */
exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        mbedtls_strerror( ret, error_buf, ERROR_BUF_SIZE );
        printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    sleep(1);
    goto init;

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

	PT_WAIT_UNTIL(&s.pt, 0);

    PT_END(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
dtls_server_init(void)
{
  s.conn = uip_udp_new((uip_ipaddr_t *)client_ip, HTONS(UDP_CLIENT_PORT));
  if (s.conn)
	  uip_udp_bind(s.conn, HTONS(UDP_SERVER_PORT));

  rx_buf = malloc(rx_buf_size);
  if (rx_buf == NULL) {
	  perror("malloc");
	  return;
  }

  PT_INIT(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
dtls_server_appcall(void)
{
  handle_dtls_server();
}
/*---------------------------------------------------------------------------*/
