#
# Copyright (c) 2004 Thorsten Kukuk <kukuk@suse.de>
# Copyright (c) 2007 Roman Rybalko <roman_rybalko@users.sf.net>
#

AUTOMAKE_OPTIONS = 1.8 dist-bzip2

AM_CFLAGS = -DUSE_TERMIO -DKLUDGELINEMODE -D_GNU_SOURCE @SSL_CFLAGS@
INCLUDES = -I$(top_srcdir) -I$(top_builddir) -I$(srcdir) -I$(top_srcdir)/misc

CLEANFILES = *~

EXTRA_DIST = ${MANS} COPYING.old autotool.sh TODO

noinst_HEADERS = defines.h externs.h ring.h telnet_locl.h types.h \
		misc-proto.h netiowrap.h ssl.h commands_auth.h \
		commands_encrypt.h commands_ssl.h

man_MANS = telnet-tls.1

bin_PROGRAMS = telnet-tls

telnet_tls_SOURCES = main.c ring.c telnet.c tn3270.c commands.c \
		network.c sys_bsd.c terminal.c utilities.c genget.c \
		netiowrap.c ssl.c commands_auth.c commands_encrypt.c \
		commands_ssl.c
telnet_tls_LDADD = misc/libmisc.a -lncurses @SSL_LIBS@

SUBDIRS = m4 misc

ACLOCAL_AMFLAGS = -I m4
