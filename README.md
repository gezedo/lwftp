lwftp
=====

A lightweight FTP client using raw API of LWIP

This client is designed with a very low level interface, and can be
used as a library to build smarter clients with more features.

Only STOR operation is supported, and server must accept binary, passive connections.
There is no storage back-end. The requester provides a callback to
source data.
When the session finishes, either successfully or not, the user provided
callback done_fn is called with the proper result code
```
static void imdone(int result)
{
    if(result == LWFTP_RESULT_OK){
        // handle end of transfer
    } else {
        // handle error
    }
}
```

LWFTP_USEDH = 0
---------------
* The callback is called once with a non null pointer to (char*), to be
used by the actual storage backend to write the location of data. The
return value is the length of available data, limited to the value of
argument maxlen.
* When the callback is called with a NULL pointer to (char*), the maxlen
argument is the number of bytes successfully sent since last call. This
shall be used by the storage backend as an acknowledge.

* Single-user, hardcoded credentials:
```
#define LWFTP_HARDCODED_CREDENTIALS
#define LWFTP_USER "username"
#define LWFTP_PASS "password"
```
* per-session credentials:
see example

As an example, the LWFTP client can be called the following way:
```
static uint file_source(const char** pptr, uint maxlen)
{
    static const uint mylen = 12345;
    static const char * const mydata = (char*)0x20000000;
    static uint offset = 0;
    uint len = 0;

    if (pptr) {
        len = mylen - offset;
        if ( len > maxlen ) len = maxlen;
        *pptr = mydata + offset;
    } else {
        offset += maxlen;
        if ( offset > mylen ) offset = mylen;
    }
    return len;
}

static void ftp_test(void)
{
    static lwftp_session_t s;	// static content for the whole FTP session
    err_t error;

    // Initialize session data
    memset(&s, 0, sizeof(s));
    IP4_ADDR(&s.server_ip, 192,168,0,31);
    s.server_port = 21;
#if LWFTP_USEDH
    s.ds.data_source = file_source;
#else
    s.data_source = file_source;
#endif
    s.done_fn = imdone;
    s.remote_path = "/data.bin";
    // set these two if not using hardcoded credentials
    s.user = "username";	// static content
    s.pass = "password";	// static content

    // Store this file
    error = lwftp_store(&s);
    if ( error != ERR_OK ) {
        LOG_ERROR("lwftp_store returned %s", lwip_strerr(error));
    }
}
```
LWFTP_USEDH = 1
---------------
* This is an "easier-going" "notsolow-level" behaviour, where the callback
function is handled by a "CGI-style" data handler.
It is called with a pointer to struct lwftp_dh (see lwftp.h),
which contains a buffer to be used by this function to write data. The buffer
size is defined by LWFTP_DH_BUFFER_SIZE. See example
There is also an additional LWFTP_DH_USER_SIZE that can be used to hold state
variables (other than the clasical "state" that belongs to struct lwftp_dh),
this is only accessed by the callback function 
The callback writes the length of available data and returns either "working"
or "done".
Returning a length of 0 bytes pauses sending, which can be resumed when lwIP
polls us after LWFTP_POLL_INTERVAL


* No hardcoded credentials

As an example, the LWFTP client can be called the following way:
```
#define LINEAS 100

static int my_lwftp_dh_fn(struct lwftp_dh *dh)
{
        if(dh->state >= LINEAS)
                return LWFTPDH_DONE;

        sprintf((char *)dh->buffer,"Line #%2d\r\n",dh->state);
        dh->length = strlen((char *)dh->buffer);
        ++dh->state;
        return LWFTPDH_WORKING;
}

static void ftp_test(void)
{
err_t error;

	// have your DNS server setup if using names
	error = lwftp_put(SERVER, PORT,  my_lwftp_dh_fn,
	   imdone, FILENAME, USER, PASS);
	if ( error != ERR_OK ) {
		LOG_ERROR("lwftp_put returned %s", lwip_strerr(error));
		/* ERR_INPROGRESS is not actually an error, the server name is
		being resolved, you might want to catch it too as an OK indication.
		If name resolve fails, your "imdone" function will get a notice;
		see returned errors in lwftp.h. lwftp_put() may return either its
		errors (see source) or lwftp_store() errors; either those defined
		in lwftp.h (positive) or belonging to the lwIP stack (negative) */
	}
}
```

