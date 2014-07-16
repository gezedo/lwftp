/*
 * lwftp.h : a lightweight FTP client using raw API of LWIP
 *
 * Copyright (c) 2014 GEZEDO
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Laurent GONZALEZ <lwip@gezedo.com>
 *
 */

#include "lwip/opt.h"
#include "lwip/ip.h"

enum lwftp_results {
  LWFTP_RESULT_OK=0,
  LWFTP_RESULT_ERR_UNKNOWN,   /** Unknown error */
  LWFTP_RESULT_ERR_CONNECT,   /** Connection to server failed */
  LWFTP_RESULT_ERR_HOSTNAME,  /** Failed to resolve server hostname */
  LWFTP_RESULT_ERR_CLOSED,    /** Connection unexpectedly closed by remote server */
  LWFTP_RESULT_ERR_TIMEOUT,   /** Connection timed out (server didn't respond in time) */
  LWFTP_RESULT_ERR_SRVR_RESP  /** Server responded with an unknown response code */
};

/** LWFTP control connection state */
typedef enum  {
  LWFTP_CLOSED=0,
  LWFTP_CONNECTED,
  LWFTP_USER_SENT,
  LWFTP_PASS_SENT,
  LWFTP_TYPE_SENT,
  LWFTP_PASV_SENT,
  LWFTP_STOR_SENT,
  LWFTP_STORING,
  LWFTP_QUIT,
  LWFTP_QUIT_SENT,
} lwftp_state_t;

#if LWFTP_USEDH

#ifndef LWFTP_DH_BUFFER_SIZE
#define LWFTP_DH_BUFFER_SIZE 256
#endif /* LWFTP_DH_BUFFER_SIZE */

struct lwftp_dh {
  u16_t state;
  u16_t length; /* Length of content in buffer */
  u8_t buffer[LWFTP_DH_BUFFER_SIZE]; /* buffer for generated content */
#ifdef LWFTP_DH_USER_SIZE
  u8_t user[LWFTP_DH_USER_SIZE];
#endif /* SMTP_DH_USER_SIZE */
};

enum lwftpdh_retvals_e {
	LWFTPDH_DONE = 0,
	LWFTPDH_WORKING
};
/** Prototype of an lwftp data handler callback function
 * It receives a struct lwftp_dh, and a buffer to write data, 
 * must return LWFTPDH_WORKING to be called again and LWFTPDH_DONE when
 * it has finished processing. This one tries to fill one TCP buffer with
 * data, your function will be repeatedly called until that happens; so if you 
 * know you'll be taking too long to serve your request, pause once in a while
 * by writing length=0 to avoid hogging system resources
 *
 * @param lwftp_dh state handling + buffer structure
 */
typedef int (*lwftp_dhcback_fn)(struct lwftp_dh *dh);

err_t lwftp_put(const char* server, u16_t port, lwftp_dhcback_fn data_fn,
	void (*done_fn)(), char *remote_path, char *user, char *pass);

struct lwftp_dh_state {
  lwftp_dhcback_fn callback_fn;  /* The function to call (again) */
  u8_t *data;
  u16_t data_len;
  u16_t state;
  struct lwftp_dh exposed;     /* the user function structure */
};

union lwftpds {
  uint (*data_source)(const char**, uint);
  struct lwftp_dh_state *dh;
};

#endif /* LWFTP_USEDH */

/** LWFTP session structure */
typedef struct {
  // User interface
  ip_addr_t     server_ip;
  u16_t         server_port;
  char          *remote_path;
#if LWFTP_USEDH
  union lwftpds ds;
#else /* LWFTP_USEDH */
  uint          (*data_source)(const char**, uint);
#endif /* LWFTP_USEDH */
  void          (*done_fn)(int);
#ifndef LWFTP_HARDCODED_CREDENTIALS
  char          *user;
  char          *pass;
#endif
  // Internal data
  lwftp_state_t   control_state;
  lwftp_state_t   data_state;
  struct tcp_pcb  *control_pcb;
  struct tcp_pcb  *data_pcb;
#if LWFTP_USEDH
  u8_t mode;      /** work as low-level data source or notsolow_level data handler */
#endif /* LWFTP_USEDH */
} lwftp_session_t;

// LWFTP API
err_t lwftp_store(lwftp_session_t *s);
