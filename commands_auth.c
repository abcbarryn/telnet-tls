/*	$OpenBSD: commands.c,v 1.20 1999/01/04 07:55:05 art Exp $	*/
/*	$NetBSD: commands.c,v 1.14 1996/03/24 22:03:48 jtk Exp $	*/

/*
 * Copyright (c) 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <telnet_locl.h>
#include <err.h>


#if	defined(AUTHENTICATION)
/*
 * The AUTHENTICATE command.
 */

typedef int (*auth_handler_t)	P((char *, char *));
struct authlist {
	const char	*name;
	const char	*help;
	auth_handler_t handler;
	int	narg;
};

static int
	auth_help P((void));

struct authlist AuthList[] = {
    { "status",	"Display current status of authentication information",
						auth_status,	0 },
    { "disable", "Disable an authentication type ('auth disable ?' for more)",
						auth_disable,	1 },
    { "enable", "Enable an authentication type ('auth enable ?' for more)",
						auth_enable,	1 },
    { "help",	0,				auth_help,		0 },
    { "?",	"Print help information",	auth_help,		0 },
    { 0 },
};

    static int
auth_help()
{
    struct authlist *c;

    for (c = AuthList; c->name; c++) {
	if (c->help) {
	    if (*c->help)
		printf("%-15s %s\r\n", c->name, c->help);
	    else
		printf("\r\n");
	}
    }
    return 0;
}

    int
auth_cmd(int argc, char *argv[])
{
    struct authlist *c;

    if (argc < 2) {
	fprintf(stderr,
	    "Need an argument to 'auth' command.  'auth ?' for help.\r\n");
	return 0;
    }

    c = (struct authlist *)
		genget(argv[1], (char **) AuthList, sizeof(struct authlist));
    if (c == 0) {
	fprintf(stderr, "'%s': unknown argument ('auth ?' for help).\r\n",
    				argv[1]);
	return 0;
    }
    if (Ambiguous(c)) {
	fprintf(stderr, "'%s': ambiguous argument ('auth ?' for help).\r\n",
    				argv[1]);
	return 0;
    }
    if (c->narg + 2 != argc) {
	fprintf(stderr,
	    "Need %s%d argument%s to 'auth %s' command.  'auth ?' for help.\r\n",
		c->narg < argc + 2 ? "only " : "",
		c->narg, c->narg == 1 ? "" : "s", c->name);
	return 0;
    }
    return((*c->handler)(argv[2], argv[3]));
}
#endif
