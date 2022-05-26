#include <config.h>

#if !defined(_commands_ssl_h) && defined(STARTTLS)
#define _commands_ssl_h

extern char starttlshelp[], stoptlshelp[], deumpcerthelp[], sslinfohelp[], sslonhelp[], ssloffhelp[];

int
starttls (int argc, char *argv[]);

int
stoptls (int argc, char *argv[]);

int
dumpcert (int argc, char *argv[]);

int
sslinfo (int argc, char *argv[]);

int
sslon (int argc, char *argv[]);

int
ssloff (int argc, char *argv[]);

#endif
