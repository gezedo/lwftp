lwftp
=====

A lightweight FTP client using raw API of LWIP

This client is designed with a very low level interface, and can be
used as a library to build smarter clients with more features.

Only STOR operation is supported, and server must accept anonymous,
binary, passive connexions.

There is no storage back-end. The requester provides a callback to
source data.
* The callback is called once with a non null pointer to (char*), to be
used by the actual storage backend to write the location of data. The
return value is the length of available data, limited to the value of
argument maxlen.
* When the callback is called with a NULL pointer to (char*), the maxlen
argument is the number of bytes successfully sent since last call. This
shall be used by the storage backend as an acknowledge.

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
    lwftp_session_t s;
    err_t error;

    // Initialize session data
    memset(&s, 0, sizeof(s));
    IP4_ADDR(&s.server_ip, 192,168,0,31);
    s.server_port = 21;
    s.data_source = file_source;
    s.remote_path = "/data.bin";

    // Store this file
    error = lwftp_store(&s);
    if ( error != ERR_OK ) {
        LOG_ERROR("lwftp_store returned %s", lwip_strerr(error));
    }
}
```
