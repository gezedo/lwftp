/*
 * lwftp.c : a lightweight FTP client using raw API of LWIP
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

#include <string.h>
#include "lwftp.h"
#include "lwip/tcp.h"
#if LWIP_DNS
#include "lwip/dns.h"
#endif

/** Enable debugging for LWFTP */
#ifndef LWFTP_DEBUG
#define LWFTP_DEBUG   LWIP_DBG_ON
#endif

#define LWFTP_TRACE   (LWFTP_DEBUG|LWIP_DBG_TRACE)
#define LWFTP_WARNING (LWFTP_DEBUG|LWIP_DBG_LEVEL_WARNING)
#define LWFTP_SERIOUS (LWFTP_DEBUG|LWIP_DBG_LEVEL_SERIOUS)
#define LWFTP_SEVERE  (LWFTP_DEBUG|LWIP_DBG_LEVEL_SEVERE)

/** TCP poll interval. Unit is 0.5 sec. */
#define LWFTP_POLL_INTERVAL      4

#define PTRNLEN(s)  s,(sizeof(s)-1)

#ifdef LWFTP_HARDCODED_CREDENTIALS
#ifndef LWFTP_USER
#error Need to define LWFTP_USER "username"
#endif
#ifndef LWFTP_PASS
#error Need to define LWFTP_PASS "password"
#endif
#if LWFTP_USEDH
#error LWFTP_USEDH is not compatible with LWFTP_HARDCODED_CREDENTIALS
#endif
#endif


#if LWFTP_USEDH
static lwftp_session_t *lwftp_alloc(u8_t mode);
static void lwftp_free(lwftp_session_t *s);
static err_t lwftp_tcp_data_poll(void *arg, struct tcp_pcb *pcb);
static int lwftp_put_data_handler(lwftp_session_t *s);
#endif /* LWFTP_USEDH */

/** Close control or data pcb
 * @param pointer to lwftp session data
 */
static err_t lwftp_pcb_close(struct tcp_pcb *tpcb)
{
  err_t error;

  tcp_err(tpcb, NULL);
  tcp_recv(tpcb, NULL);
  tcp_sent(tpcb, NULL);
  error = tcp_close(tpcb);
  if ( error != ERR_OK ) {
    LWIP_DEBUGF(LWFTP_SEVERE, ("lwftp:pcb close failure, not implemented\n"));
  }
  return ERR_OK;
}

/** Send data
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param number of bytes sent
 */
static err_t lwftp_send_next_data(lwftp_session_t *s)
{
  const char *data;
  int len = 0;
  err_t error = ERR_OK;
#if LWFTP_USEDH
  if (s->ds.data_source) {
    len = s->ds.data_source(&data, s->data_pcb->mss);
#else /* LWFTP_USEDH */
  if (s->data_source) {
    len = s->data_source(&data, s->data_pcb->mss);
#endif /* LWFTP_USEDH */
    if (len) {
      LWIP_DEBUGF(LWFTP_TRACE, ("lwftp:sending %d bytes of data\n",len));
      error = tcp_write(s->data_pcb, data, len, 0);
      if (error!=ERR_OK) {
        LWIP_DEBUGF(LWFTP_SEVERE, ("lwftp:write failure (%s), not implemented\n",lwip_strerr(error)));
      }
    }
  }
  if (!len) {
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp:end of file\n"));
    lwftp_pcb_close(s->data_pcb);
    s->data_pcb = NULL;
  }
  return ERR_OK;
}

/** Handle data connection incoming data
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param pointer to incoming pbuf
 * @param state of incoming process
 */
static err_t lwftp_data_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
  LWIP_DEBUGF(LWFTP_SEVERE, ("lwftp:nothing implemented (line %d)\n",__LINE__));
  return ERR_ABRT;
}

#if LWFTP_USEDH
/** Handle data process
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param number of bytes sent (if coming from sent)
 */
static err_t lwftp_data_process(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
  lwftp_session_t *s = (lwftp_session_t*)arg;

  switch(s->mode){
  case 1:
    if(lwftp_put_data_handler(s)==0){
      lwftp_pcb_close(s->data_pcb);
      s->data_pcb = NULL;
    }
    break;
  default:
    if ( s->ds.data_source ) {
      s->ds.data_source(NULL, len);
    }
    return lwftp_send_next_data(s);
  }
  return ERR_OK;
}
#endif /* LWFTP_USEDH */

/** Handle data connection acknowledge of sent data
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param number of bytes sent
 */
static err_t lwftp_data_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
#if LWFTP_USEDH
  return lwftp_data_process(arg, tpcb, len);
#else /* LWFTP_USEDH */
  lwftp_session_t *s = (lwftp_session_t*)arg;
  if ( s->data_source ) {
    s->data_source(NULL, len);
  }
  return lwftp_send_next_data(s);
#endif /* LWFTP_USEDH */
}

/** Handle data connection error
 * @param pointer to lwftp session data
 * @param state of connection
 */
static void lwftp_data_err(void *arg, err_t err)
{
  LWIP_UNUSED_ARG(err);
  if (arg != NULL) {
    lwftp_session_t *s = (lwftp_session_t*)arg;
    LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:failed/error connecting for data to server (%s)\n",lwip_strerr(err)));
    s->control_state = LWFTP_QUIT;  // gracefully exit on data error
  }
}

/** Process newly connected PCB
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param state of connection
 */
static err_t lwftp_data_connected(void *arg, struct tcp_pcb *tpcb, err_t err)
{
  lwftp_session_t *s = (lwftp_session_t*)arg;

  if ( err == ERR_OK ) {
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp:connected for data to server\n"));
    s->data_state = LWFTP_CONNECTED;
  } else {
    LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:err in data_connected (%s)\n",lwip_strerr(err)));
  }
  return err;
}

/** Open data connection for passive transfer
 * @param pointer to lwftp session data
 * @param pointer to incoming PASV response
 */
static err_t lwftp_data_open(lwftp_session_t *s, struct pbuf *p)
{
  err_t error;
  char *ptr;
  ip_addr_t data_server;
  u16_t data_port;

  // Find server connection parameter
  ptr = strchr(p->payload, '(');
  if (!ptr) return ERR_BUF;
  ip4_addr1(&data_server) = strtoul(ptr+1,&ptr,10);
  ip4_addr2(&data_server) = strtoul(ptr+1,&ptr,10);
  ip4_addr3(&data_server) = strtoul(ptr+1,&ptr,10);
  ip4_addr4(&data_server) = strtoul(ptr+1,&ptr,10);
  data_port  = strtoul(ptr+1,&ptr,10) << 8;
  data_port |= strtoul(ptr+1,&ptr,10) & 255;
  if (*ptr!=')') return ERR_BUF;

  // Open data session
  tcp_arg(s->data_pcb, s);
  tcp_err(s->data_pcb, lwftp_data_err);
  tcp_recv(s->data_pcb, lwftp_data_recv);
  tcp_sent(s->data_pcb, lwftp_data_sent);
#if LWFTP_USEDH
  if(s->mode){
    tcp_poll(s->data_pcb, lwftp_tcp_data_poll, LWFTP_POLL_INTERVAL);
  }
#endif /* LWFTP_USEDH */
  error = tcp_connect(s->data_pcb, &data_server, data_port, lwftp_data_connected);
  return error;
}

/** Send a message to control connection
 * @param pointer to lwftp session data
 * @param pointer to message string
 */
static err_t lwftp_send_msg(lwftp_session_t *s, char* msg, size_t len)
{
  err_t error;

  LWIP_DEBUGF(LWFTP_TRACE,("lwftp:sending %s",msg));
  error = tcp_write(s->control_pcb, msg, len, 0);
  if ( error != ERR_OK ) {
      LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:cannot write (%s)\n",lwip_strerr(error)));
  }
  return error;
}

/** Close control connection
 * @param pointer to lwftp session data
 * @param result to pass to callback fn (if called)
 */
static void lwftp_control_close(lwftp_session_t *s, int result)
{
  if (s->data_pcb) {
    lwftp_pcb_close(s->data_pcb);
    s->data_pcb = NULL;
  }
  if (s->control_pcb) {
    lwftp_pcb_close(s->control_pcb);
    s->control_pcb = NULL;
  }
  if ( (result >= 0) && s->done_fn ) {
    s->done_fn(result);
  }
  s->control_state = LWFTP_CLOSED;
#if LWFTP_USEDH
  if(s->mode){
    lwftp_free(s);
  }
#endif /* LWFTP_USEDH */
}

/** Main client state machine
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param pointer to incoming data
 */
static void lwftp_control_process(lwftp_session_t *s, struct tcp_pcb *tpcb, struct pbuf *p)
{
  uint response = 0;

  // Try to get response number
  if (p) {
    response = strtoul(p->payload, NULL, 10);
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp:got response %d\n",response));
  }

  switch (s->control_state) {
    case LWFTP_CONNECTED:
      if (response>0) {
        if (response==220) {
          lwftp_send_msg(s, PTRNLEN("USER "));
#ifdef LWFTP_HARDCODED_CREDENTIALS
          lwftp_send_msg(s, LWFTP_USER, strlen(LWFTP_USER));
#else
          lwftp_send_msg(s, s->user, strlen(s->user));
#endif
          lwftp_send_msg(s, PTRNLEN("\n"));
          s->control_state = LWFTP_USER_SENT;
        } else {
          s->control_state = LWFTP_QUIT;
        }
      }
      break;
    case LWFTP_USER_SENT:
      if (response>0) {
        if (response==331) {
          lwftp_send_msg(s, PTRNLEN("PASS "));
#ifdef LWFTP_HARDCODED_CREDENTIALS
          lwftp_send_msg(s, LWFTP_PASS, strlen(LWFTP_PASS));
#else
          lwftp_send_msg(s, s->pass, strlen(s->pass));
#endif
          lwftp_send_msg(s, PTRNLEN("\n"));
          s->control_state = LWFTP_PASS_SENT;
        } else {
          s->control_state = LWFTP_QUIT;
        }
      }
      break;
    case LWFTP_PASS_SENT:
      if (response>0) {
        if (response==230) {
          lwftp_send_msg(s, PTRNLEN("TYPE I\n"));
          s->control_state = LWFTP_TYPE_SENT;
        } else {
          s->control_state = LWFTP_QUIT;
        }
      }
      break;
    case LWFTP_TYPE_SENT:
      if (response>0) {
        if (response==200) {
          lwftp_send_msg(s, PTRNLEN("PASV\n"));
          s->control_state = LWFTP_PASV_SENT;
        } else {
          s->control_state = LWFTP_QUIT;
        }
      }
      break;
    case LWFTP_PASV_SENT:
      if (response>0) {
        if (response==227) {
          lwftp_data_open(s,p);
          lwftp_send_msg(s, PTRNLEN("STOR "));
          lwftp_send_msg(s, s->remote_path, strlen(s->remote_path));
          lwftp_send_msg(s, PTRNLEN("\n"));
          s->control_state = LWFTP_STOR_SENT;
        } else {
          s->control_state = LWFTP_QUIT;
        }
      }
      break;
    case LWFTP_STOR_SENT:
      if (response>0) {
        if (response==150) {
          s->control_state = LWFTP_STORING;
          lwftp_data_sent(s,NULL,0);
        } else {
          s->control_state = LWFTP_QUIT;
        }
      }
      break;
    case LWFTP_STORING:
      if (response>0) {
        if (response==226) {
	  s->data_state = LWFTP_STORING;  // signal transfer OK
        } else {
          LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:expected 226, received %d\n",response));
        }
        s->control_state = LWFTP_QUIT;
      }
      break;
    case LWFTP_QUIT_SENT:
      if (response>0) {
	int result = LWFTP_RESULT_ERR_SRVR_RESP;
        if (response==221) {
	  if (s->data_state == LWFTP_STORING){ // check for transfer OK
	    result = LWFTP_RESULT_OK;
          }
        } else {
          LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:expected 221, received %d\n",response));
        }
        lwftp_control_close(s, result);
      }
      break;
    default:
      LWIP_DEBUGF(LWFTP_SEVERE, ("lwftp:unhandled state (%d)\n",s->control_state));
  }

  // Quit when required to do so
  if ( s->control_state == LWFTP_QUIT ) {
    lwftp_send_msg(s, PTRNLEN("QUIT\n"));
    s->control_state = LWFTP_QUIT_SENT;
  }

}

/** Handle control connection incoming data
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param pointer to incoming pbuf
 * @param state of incoming process
 */
static err_t lwftp_control_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
  lwftp_session_t *s = (lwftp_session_t*)arg;

  if ( err == ERR_OK ) {
    if (p) {
      tcp_recved(tpcb, p->tot_len);
      lwftp_control_process(s, tpcb, p);
    } else {
      LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:connection closed by remote host\n"));
      lwftp_control_close(s, LWFTP_RESULT_ERR_CLOSED);
    }
  } else {
    LWIP_DEBUGF(LWFTP_SERIOUS, ("lwftp:failed to receive (%s)\n",lwip_strerr(err)));
    lwftp_control_close(s, LWFTP_RESULT_ERR_UNKNOWN);
  }
  return err;
}

/** Handle control connection acknowledge of sent data
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param number of bytes sent
 */
static err_t lwftp_control_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
  LWIP_DEBUGF(LWFTP_TRACE, ("lwftp:successfully sent %d bytes\n",len));
  return ERR_OK;
}

/** Handle control connection error
 * @param pointer to lwftp session data
 * @param state of connection
 */
static void lwftp_control_err(void *arg, err_t err)
{
  LWIP_UNUSED_ARG(err);
  if (arg != NULL) {
    lwftp_session_t *s = (lwftp_session_t*)arg;
    int result;
    if( s->control_state == LWFTP_CLOSED ) {
      LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:failed to connect to server (%s)\n",lwip_strerr(err)));
      result = LWFTP_RESULT_ERR_CONNECT;
    } else {
      LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:connection closed by remote host\n"));
      result = LWFTP_RESULT_ERR_CLOSED;
    }
    lwftp_control_close(s, result);
  }
}


/** Process newly connected PCB
 * @param pointer to lwftp session data
 * @param pointer to PCB
 * @param state of connection
 */
static err_t lwftp_control_connected(void *arg, struct tcp_pcb *tpcb, err_t err)
{
  lwftp_session_t *s = (lwftp_session_t*)arg;

  if ( err == ERR_OK ) {
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp:connected to server\n"));
      s->control_state = LWFTP_CONNECTED;
  } else {
    LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:err in control_connected (%s)\n",lwip_strerr(err)));
  }
  return err;
}


/** Store data to a remote file, the low-level interface
 * @param Session structure
 */
err_t lwftp_store(lwftp_session_t *s)
{
  err_t error;

  // Check user supplied data
  if ((s->control_state!=LWFTP_CLOSED) || !s->remote_path || s->control_pcb || s->data_pcb
#ifndef LWFTP_HARDCODED_CREDENTIALS
    || !s->user || !s->pass
#endif
    ) {
    LWIP_DEBUGF(LWFTP_WARNING, ("lwftp:invalid session data\n"));
    return ERR_ARG;
  }
  // Get sessions pcb
  s->control_pcb = tcp_new();
  if (!s->control_pcb) {
    LWIP_DEBUGF(LWFTP_SERIOUS, ("lwftp:cannot alloc control_pcb (low memory?)\n"));
    error = ERR_MEM;
    goto exit;
  }
  s->data_pcb = tcp_new();
  if (!s->data_pcb) {
    LWIP_DEBUGF(LWFTP_SERIOUS, ("lwftp:cannot alloc data_pcb (low memory?)\n"));
    error = ERR_MEM;
    goto close_pcb;
  }
  // Open control session
  tcp_arg(s->control_pcb, s);
  tcp_err(s->control_pcb, lwftp_control_err);
  tcp_recv(s->control_pcb, lwftp_control_recv);
  tcp_sent(s->control_pcb, lwftp_control_sent);
  error = tcp_connect(s->control_pcb, &s->server_ip, s->server_port, lwftp_control_connected);
  if ( error == ERR_OK ) goto exit;

  LWIP_DEBUGF(LWFTP_SERIOUS, ("lwftp:cannot connect control_pcb (%s)\n", lwip_strerr(error)));

close_pcb:
  // Release pcbs in case of failure
  lwftp_control_close(s, -1);

exit:
  return error;
}

#if LWFTP_USEDH

static lwftp_session_t *
lwftp_alloc(u8_t mode)
{
  lwftp_session_t *s;

  LWIP_DEBUGF(LWFTP_TRACE, ("lwftp_alloc\n"));
  s = mem_malloc(sizeof(lwftp_session_t));
  if (s == NULL) {
    return NULL;
  }
  memset(s, 0, sizeof(lwftp_session_t));
  if(mode){
    s->ds.dh = mem_malloc(sizeof(struct lwftp_dh_state));
    if (s->ds.dh == NULL) {
      mem_free(s);
      return NULL;
    }
    memset(s->ds.dh, 0, sizeof(struct lwftp_dh_state));
    s->mode = mode;
  }
  return s;
}

static void
lwftp_free(lwftp_session_t *s)
{
  LWIP_DEBUGF(LWFTP_TRACE, ("lwftp_free\n"));
  LWIP_ASSERT("s != NULL", s != NULL);
  if (s->mode && (s->ds.dh != NULL)) {
    mem_free(s->ds.dh);
  }
  mem_free(s);
}

#if LWIP_DNS
/** DNS callback
 * If ipaddr is non-NULL, resolving succeeded, otherwise it failed.
 */
static void
lwftp_dns_found(const char* hostname, ip_addr_t *ipaddr, void *arg)
{
  lwftp_session_t *s = (lwftp_session_t *)arg;
  err_t err = LWFTP_RESULT_ERR_HOSTNAME;
  LWIP_UNUSED_ARG(hostname);

  if (ipaddr != NULL) {
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp: _dns_found: hostname resolved to %08X\n", ipaddr->addr));
    s->server_ip = *ipaddr;
    err = lwftp_store(s);
  } else {
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp: _dns_found: failed to resolve hostname: %s\n",
      hostname));
  }
  if ( err != ERR_OK){
    if ( s->done_fn ) {
      s->done_fn(err);
    }
    lwftp_free(s);
  }
}
#endif /* LWIP_DNS */

/** Raw API TCP poll callback */
static err_t
lwftp_tcp_data_poll(void *arg, struct tcp_pcb *pcb)
{
  if (arg != NULL) {
    lwftp_session_t *s = (lwftp_session_t *)arg;
    return lwftp_data_process(s, pcb, 0);
  }
  return ERR_OK;
}

/** Store data to a remote file, the notsolow-level interface
 *
 * @param server server address (NULL-terminated string), either name or IP
 * @param port port number
 * @param data_fn the data generating/sending function (callback)
 * @param done_fn the (callback) function to call when finished (either successfully or not)
 * @param user user name (NULL-terminated string)
 * @param pass user password (NULL-terminated string)
 * @returns - ERR_OK if structures were allocated and no error occured starting the connection
 *            (this does not mean the transfer has been successfully ended!)
 *          - ERR_INPROGRESS if server name is being resolved (check done_fn calling parameter)
 *          - another err_t on error (see lwftp_store)
 */
err_t
lwftp_put(const char* server, u16_t port, lwftp_dhcback_fn data_fn,
	void (*done_fn)(), char *remote_path, char *user, char *pass)
{
err_t err = ERR_OK;
ip_addr_t addr;
lwftp_session_t *s;

  s = lwftp_alloc(LWFTP_USEDH);
  if( s == NULL ){
    return ERR_MEM;
  }
#if LWIP_DNS
  err = dns_gethostbyname(server, &addr, lwftp_dns_found, s);
#else /* LWIP_DNS */
  addr.addr = ipaddr_addr(server);
  if(addr.addr == IPADDR_NONE){
    lwftp_free(s);
    return ERR_ARG;
  }
#endif /* LWIP_DNS */
  if ((err == ERR_OK) || (err == ERR_INPROGRESS)) {
    s->server_ip = addr;	// meaningless if being resolved, will be overwritten later
    s->server_port = port;
    s->ds.dh->callback_fn = data_fn;
    s->done_fn = done_fn;
    s->remote_path = remote_path;
    s->user = user;
    s->pass = pass;
    if ((err == ERR_OK) && ((err = lwftp_store(s)) != ERR_OK)){
      lwftp_free(s);
    }
  } else {
    LWIP_DEBUGF(LWFTP_TRACE, ("dns_gethostbyname failed: %d\n", (int)err));
  }
  return err;
}

#define LWFTPDHALLDATASENT  2
#define LWFTPDHSOMEDATASENT 1

/** Elementary sub-function to send data
 *
 * @returns: LWFTPDHALLDATASENT all data has been written
 *           LWFTPDHSOMEDATASENT some data has been written
 *           0 no data has been written
 */
static int
_lwftp_send_data(struct tcp_pcb *pcb, char **from, u16_t *howmany)
{
  err_t err;
  u16_t len = *howmany;

  len = (u16_t)LWIP_MIN(len, tcp_sndbuf(pcb));
  err = tcp_write(pcb, *from, len, TCP_WRITE_FLAG_COPY);
  if (err == ERR_OK) {
    *from += len;
    if((*howmany -= len) > 0)
      return LWFTPDHSOMEDATASENT;
    return LWFTPDHALLDATASENT;
  }
  return 0;
}

enum lwftpdh_handler_state {
  LWFTPDH_SENDING,         /* Serving the user function generating body content */
  LWFTPDH_STOP             /* User function stopped, closing */
};

static int
lwftp_put_data_handler(lwftp_session_t *s)
{
  struct lwftp_dh_state *dh = s->ds.dh;
  int res = 0, ret;
  LWIP_ASSERT("s != NULL", s != NULL);
  LWIP_ASSERT("dh != NULL", dh != NULL);

  /* resume any leftovers from prior memory constraints */
  if(dh->data_len){
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp_put_data_handler: resume\n"));
    if((res = _lwftp_send_data(s->data_pcb, (char **)&dh->data, &dh->data_len))
        != LWFTPDHALLDATASENT) {
      return 1;
    }
  }
  ret = res;
  /* all data on buffer has been queued, resume execution */
  if(dh->state == LWFTPDH_SENDING){
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp_put_data_handler: run\n"));
    do {
  	  ret |= res;  /* remember if we once queued something to send */
      dh->exposed.length = 0;
      if(dh->callback_fn(&dh->exposed) == LWFTPDH_DONE){
        dh->state = LWFTPDH_STOP;
      }
      dh->data = dh->exposed.buffer;
      dh->data_len = dh->exposed.length;
      LWIP_DEBUGF(LWFTP_TRACE, ("lwftp_put_data_handler: trying to send %u bytes\n", (unsigned int)dh->data_len));
    } while(dh->data_len && 
           ((res = _lwftp_send_data(s->data_pcb, (char **)&dh->data, &dh->data_len)) == LWFTPDHALLDATASENT)
           && (dh->state != LWFTPDH_STOP));
  }
  if((dh->state != LWFTPDH_SENDING) && (ret != LWFTPDHSOMEDATASENT)){
    LWIP_DEBUGF(LWFTP_TRACE, ("lwftp_put_data_handler: stop\n"));
    return 0;
  }
  LWIP_DEBUGF(LWFTP_TRACE, ("lwftp_put_data_handler: pause\n"));
  return 1;
}

#endif /* LWFTP_USEDH */
