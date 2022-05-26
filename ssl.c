#include <config.h>

#ifdef STARTTLS

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <telnet_locl.h>

int ssl = 0;

SSL * ssl_conn = NULL;
SSL_CTX * ssl_ctx = NULL;
char * certfile = NULL;
certfiletpye_t certfiletype;

void ssl_print_error(void)
{
	unsigned long err;
	char errstr[200];
	while(err = ERR_get_error())
	{
		fprintf(stderr, "Telnet: SSL: %s\n", ERR_error_string(err, errstr));
	}
}

int ssl_init_ctx(void)
{
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	FILE *f = NULL;
	
	if(!ssl_ctx)
	{
		SSL_library_init();
		SSL_load_error_strings();
		ssl_ctx = SSL_CTX_new(SSLv23_method());
		if(!ssl_ctx)
		{
			ssl_print_error();
			return -2;
		}
		if(certfile)
		{
			switch(certfiletype)
			{
			case type_PEM:
				if(SSL_CTX_use_certificate_file(ssl_ctx, certfile, SSL_FILETYPE_PEM ) != 1)
				{
					ssl_print_error();
					return -2;
				}
				if(SSL_CTX_use_PrivateKey_file(ssl_ctx, certfile, SSL_FILETYPE_PEM ) != 1)
				{
					ssl_print_error();
					printf("Unable to find PrivateKey in %s. Not giving up.\r\n",certfile);
				}
				break;
			case type_DER:
				f = fopen(certfile,"rb");
				if(!f)
				{
					printf("Unable to open file %s (%s).\r\n",certfile,strerror(errno));
					return -1;
				}
				cert = d2i_X509_fp(f, &cert);
				if(!cert)
				{
					ssl_print_error();
					printf("Unable to load certificate from %s.",certfile);
					goto ERR_BREAK;
				}
				rewind(f);
				pkey = PEM_read_PrivateKey(f, &pkey, NULL, NULL);
				if(!pkey)
				{
					ssl_print_error();
					printf("Unable to find PrivateKey in %s. Not giving up.\r\n",certfile);
				}
				if(SSL_CTX_use_certificate(ssl_ctx, cert)!=1)
				{
					ssl_print_error();
					printf("Unable to set certificate on SSL context.\r\n");
					goto ERR_BREAK;
				}
				if(pkey)
					if(SSL_CTX_use_PrivateKey(ssl_ctx, pkey)!=1)
					{
						ssl_print_error();
						printf("Unable to set PrivateKey on SSL context.\r\n");
						goto ERR_BREAK;
					}
				break;
ERR_BREAK:
				fclose(f);
				return -2;
			default:
				printf("Unknown certificate file type: %d\r\n",certfiletype);
				return -1;
			}
		}
		return 1;
	}
	return 0;
}

int ssl_init(void)
{
	int ret;
	if((ret=ssl_init_ctx()) < 0)
		return ret;
	
	if(ssl_conn)
		SSL_free(ssl_conn);
	ssl_conn = SSL_new(ssl_ctx);
	if(!ssl_conn)
	{
		ssl_print_error();
		return -2;
	}

	if(SSL_set_fd(ssl_conn, net) != 1)
	{
		ssl_print_error();
		return -2;
	}

	NetNonblockingIO(net, 0);

	if(SSL_connect(ssl_conn)<1)
	{
		ssl_print_error();
		NetNonblockingIO(net, 1);
		return -2;
	}

	NetNonblockingIO(net, 1);

	ssl = 1;
	return 0;
}

int ssl_read(void * buf, int num)
{
	int cnt;

	NetNonblockingIO(net, 0);

	cnt = SSL_read(ssl_conn, buf, num);
	if(cnt==0)
	{
		if(SSL_shutdown(ssl_conn)<1)
		{
			ssl_print_error();
			NetNonblockingIO(net, 1);
			return -2;
		}
	}
	if(cnt<0)
	{
		ssl_print_error();
		NetNonblockingIO(net, 1);
		return -2;
	}

	NetNonblockingIO(net, 1);

	return cnt;
}

int ssl_write(const void * buf, int num)
{
	int cnt;

	NetNonblockingIO(net, 0);

	cnt = SSL_write(ssl_conn, buf, num);
	if(cnt<0)
	{
		ssl_print_error();
		NetNonblockingIO(net, 1);
		return -2;
	}

	NetNonblockingIO(net, 1);

	return cnt;
}

int ssl_done(void)
{
	NetNonblockingIO(net, 0);

	if(SSL_shutdown(ssl_conn)<1)
	{
		ssl_print_error();
		NetNonblockingIO(net, 1);
		return -2;
	}

	SSL_free(ssl_conn);
	ssl_conn = NULL;

	NetNonblockingIO(net, 1);

	ssl = 0;
	return 0;
}

int ssl_dump_peer_cert(const char * fname)
{
	FILE *f;
	X509 *peer;
	int result = 0;

	if (!ssl_conn)
	{
		printf("You need to establish SSL connection first.\r\n");
		return 0;
	}

	f=fopen(fname,"wb");
	if(!f)
	{
		printf("Can't open file %s for writing (%s).\r\n", fname, strerror(errno));
		return 0;
	}

	peer=SSL_get_peer_certificate(ssl_conn);
	if(peer)
	{
		if (i2d_X509_fp(f, peer)>=0)
		{
			printf("Peer certificate dumped to %s.\r\n", fname );
			result = 1;
		}
		else
		{
			ssl_print_error();
			result = 0;
		}
		X509_free(peer);
	}

	fclose(f);

	return result;
}


#define STDOUT STDOUT_FILENO

/* borrowed from s_client.c */
#define PEM_write_X509(f,x) PEM_ASN1_write((int (*)())i2d_X509,PEM_STRING_X509,f,(char *)x, NULL,NULL,0,NULL,NULL)
int print_ssl_conn_info()
{
	X509 *peer=NULL;
	char *p;
	static const char *space="                ";
	char buf[BUFSIZ];
	STACK_OF(X509) *sk;
	STACK_OF(X509_NAME) *sk2;
	SSL_CIPHER *c;
	X509_NAME *xn;
	int j,i;
	const COMP_METHOD *comp, *expansion;

	int got_a_chain = 0;

	if (!ssl_conn)
	{
		printf("You need to establish SSL connection first.\r\n");
		return 0;
	}

	sk=SSL_get_peer_cert_chain(ssl_conn);
	if (sk != NULL)
	{
		got_a_chain = 1; /* we don't have it for SSL2 (yet) */

		printf("---\r\nCertificate chain\r\n");
		for (i=0; i<sk_X509_num(sk); i++)
		{
			X509_NAME_oneline(X509_get_subject_name(
					sk_X509_value(sk,i)),buf,sizeof buf);
			printf("%2d s:%s\r\n",i,buf);
			X509_NAME_oneline(X509_get_issuer_name(
					sk_X509_value(sk,i)),buf,sizeof buf);
			printf("   i:%s\r\n",buf);
			PEM_write_X509(stdout,(X509*)sk_X509_value(sk,i));
		}
	}

	printf("---\r\n");
	peer=SSL_get_peer_certificate(ssl_conn);
	if (peer != NULL)
	{
		printf("Server certificate\r\n");
		if (!got_a_chain) /* Redundant if we showed the whole chain */
			PEM_write_X509(stdout,peer);
		X509_NAME_oneline(X509_get_subject_name(peer),
				buf,sizeof buf);
		printf("subject=%s\r\n",buf);
		X509_NAME_oneline(X509_get_issuer_name(peer),
				buf,sizeof buf);
		printf("issuer=%s\r\n",buf);
	}
	else
		printf("no peer certificate available\r\n");

	sk2=SSL_get_client_CA_list(ssl_conn);
	if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0))
	{
		printf("---\r\nAcceptable client certificate CA names\r\n");
		for (i=0; i<sk_X509_NAME_num(sk2); i++)
		{
			xn=sk_X509_NAME_value(sk2,i);
			X509_NAME_oneline(xn,buf,sizeof(buf));
			write(STDOUT,buf,strlen(buf));
			write(STDOUT,"\r\n",2);
		}
	}
	else
	{
		printf("---\r\nNo client certificate CA names sent\r\n");
	}
	p=SSL_get_shared_ciphers(ssl_conn,buf,sizeof buf);
	if (p != NULL)
	{
		/* This works only for SSL 2.  In later protocol
		 * versions, the client does not know what other
		 * ciphers (in addition to the one to be used
		 * in the current connection) the server supports. */

		printf("---\r\nCiphers common between both SSL endpoints:\r\n");
		j=i=0;
		while (*p)
		{
			if (*p == ':')
			{
				write(STDOUT,space,15-j%25);
				i++;
				j=0;
				write(STDOUT,((i%3)?" ":"\r\n"),1);
			}
			else
			{
				write(STDOUT,p,1);
				j++;
			}
			p++;
		}
		write(STDOUT,"\r\n",2);
	}

	printf("---\r\nSSL has read %ld bytes and written %ld bytes\r\n",
			BIO_number_read(SSL_get_rbio(ssl_conn)),
			BIO_number_written(SSL_get_wbio(ssl_conn)));

#ifndef __APPLE__
	printf(((ssl_conn->hit)?"---\r\nReused, ":"---\r\nNew, "));
#endif
	c=SSL_get_current_cipher(ssl_conn);
	printf("%s, Cipher is %s\r\n",
			SSL_CIPHER_get_version(c),
			SSL_CIPHER_get_name(c));
	if (peer != NULL) {
		EVP_PKEY *pktmp;
		pktmp = X509_get_pubkey(peer);
		printf("Server public key is %d bit\r\n",
				EVP_PKEY_bits(pktmp));
		EVP_PKEY_free(pktmp);
	}
#ifdef OPENSSL_NO_COMP
	comp=SSL_get_current_compression(ssl_conn);
	expansion=SSL_get_current_expansion(ssl_conn);
	printf("Compression: %s\r\n",
			comp ? SSL_COMP_get_name(comp) : "NONE");
	printf("Expansion: %s\r\n",
			expansion ? SSL_COMP_get_name(expansion) : "NONE");
#endif
	SSL_SESSION_print_fp(stdout,SSL_get_session(ssl_conn));
	printf("---\r\n");

	if (peer != NULL)
		X509_free(peer);

	return 1;
}

#endif
