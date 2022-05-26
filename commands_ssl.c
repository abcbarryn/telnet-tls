#include <telnet_locl.h>

#if	defined(STARTTLS)
/*
 * SSL-related commands
 */

char 
  starttlshelp[] = "start TLS negotiation",
  stoptlshelp[] = "stop TLS session",
  deumpcerthelp[] = "dump peer certificate into a file (DER)",
  sslinfohelp[] = "show SSL connection info",
  ssloffhelp[] = "temporary disable ssl (for testing)",
  sslonhelp[] = "enable ssl again when it was temporary disabled (for testing)";

/*
 * STARTTLS command.
 */
int
starttls (int argc, char *argv[])
{
    ssl_init();
    return 1;
}

/*
 * STOPTLS command.
 */
int
stoptls (int argc, char *argv[])
{
    ssl_done();
    return 1;
}

/*
 * DUMPCERT command.
 */
int
dumpcert (int argc, char *argv[])
{
	if (argc<2 || argv[1][0] == '?' )
	{
		printf("usage: %s file\r\n",argv[0]);
		return 0;
	}
    return ssl_dump_peer_cert(argv[1]);
}

/*
 * SSLINFO command.
 */
int sslinfo (int argc, char *argv[])
{
	return print_ssl_conn_info();
}

/*
 * SSLON command
 */
int sslon (int argc, char *argv[])
{
	if (ssl_conn)
	{
		if (ssl)
			printf("Already enabled.\r\n");
		else
			ssl = 1;
		return 1;
	}
	else
	{
		printf("You can't use this command when ssl isn't established.\r\n");
		return 0;
	}
}

/*
 * SSLOFF command
 */
int ssloff (int argc, char *argv[])
{
	if (ssl_conn)
	{
		if (ssl)
			ssl = 0;
		else
			printf("Already disabled.\r\n");
		return 1;
	}
	else
	{
		printf("You can't use this command when ssl isn't established.\r\n");
		return 0;
	}
}

#endif
