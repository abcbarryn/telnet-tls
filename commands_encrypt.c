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


#if    defined(ENCRYPTION)
/*
 * The ENCRYPT command.
 */

typedef	int (*encrypt_handler_t) P((char *, char *, char *));
struct encryptlist {
       const char    *name;
       const char    *help;
       encrypt_handler_t handler;
       int     needconnect;
       int     minarg;
       int     maxarg;
};
 
static int
       encrypt_help (void);

struct encryptlist EncryptList[] = {
    { "enable", "Enable encryption. ('encrypt enable ?' for more)",
                                               EncryptEnable, 1, 1, 2 },
    { "disable", "Disable encryption. ('encrypt enable ?' for more)",
                                               EncryptDisable, 0, 1, 2 },
    { "type", "Set encryption type. ('encrypt type ?' for more)",
                                               EncryptType, 0, 1, 1 },
    { "start", "Start encryption. ('encrypt start ?' for more)",
                                               EncryptStart, 1, 0, 1 },
    { "stop", "Stop encryption. ('encrypt stop ?' for more)",
                                               EncryptStop, 1, 0, 1 },
    { "input", "Start encrypting the input stream",
                                               EncryptStartInput, 1, 0, 0 },
    { "-input", "Stop encrypting the input stream",
                                               EncryptStopInput, 1, 0, 0 },
    { "output", "Start encrypting the output stream",
                                               EncryptStartOutput, 1, 0, 0 },
    { "-output", "Stop encrypting the output stream",
                                               EncryptStopOutput, 1, 0, 0 },

    { "status",        "Display current status of authentication information",
                                               EncryptStatus,  0, 0, 0 },
    { "help",  0,                              encrypt_help,    0, 0, 0 },
    { "?",     "Print help information",       encrypt_help,    0, 0, 0 },
    { 0 },
};

static int
encrypt_help(void)
{
    struct encryptlist *c;

    for (c = EncryptList; c->name; c++) {
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
encrypt_cmd(int argc, char **argv)
{
    struct encryptlist *c;

    if (argc < 2) {
	fprintf(stderr, "Need at least one argument for 'encrypt' command.\n");
	fprintf(stderr, "('encrypt ?' for help)\n");
	return 0;
    }

    c = (struct encryptlist *)
               genget(argv[1], (char **) EncryptList, sizeof(struct encryptlist));
    if (c == 0) {
        fprintf(stderr, "'%s': unknown argument ('encrypt ?' for help).\r\n",
                               argv[1]);
        return 0;
    }
    if (Ambiguous(c)) {
        fprintf(stderr, "'%s': ambiguous argument ('encrypt ?' for help).\r\n",
                               argv[1]);
        return 0;
    }
    argc -= 2;
    if (argc < c->minarg || argc > c->maxarg) {
       if (c->minarg == c->maxarg) {
           fprintf(stderr, "Need %s%d argument%s ",
               c->minarg < argc ? "only " : "", c->minarg,
               c->minarg == 1 ? "" : "s");
       } else {
           fprintf(stderr, "Need %s%d-%d arguments ",
               c->maxarg < argc ? "only " : "", c->minarg, c->maxarg);
       }
       fprintf(stderr, "to 'encrypt %s' command.  'encrypt ?' for help.\r\n",
               c->name);
       return 0;
    }
    if (c->needconnect && !connected) {
       if (!(argc && (isprefix(argv[2], "help") || isprefix(argv[2], "?")))) {
           printf("?Need to be connected first.\r\n");
           return 0;
       }
    }
    return ((*c->handler)(argc > 0 ? argv[2] : 0,
                       argc > 1 ? argv[3] : 0,
                       argc > 2 ? argv[4] : 0));
}
#endif
