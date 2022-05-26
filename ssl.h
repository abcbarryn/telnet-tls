#ifndef _SSL_H
#define _SSL_H

typedef enum _certfiletype_t
{
	type_DER,
	type_PEM
} certfiletpye_t;

extern int ssl;
extern char * certfile;
extern certfiletpye_t certfiletype;

#include <openssl/ssl.h>
extern SSL * ssl_conn;


int ssl_init_ctx(void);
int ssl_init(void);
int ssl_read(void * buf, int num);
int ssl_write(const void * buf, int num);
int ssl_done(void);
int ssl_dump_peer_cert(const char * fname);
int print_ssl_conn_info();

#endif
