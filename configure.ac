#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(telnet-tls.1)
AM_INIT_AUTOMAKE(telnet-tls, 0.3.3)
AM_CONFIG_HEADER([config.h])

PKG_PROG_PKG_CONFIG

AC_ARG_ENABLE(tls,
  [  --disable-tls	turn off TLS support [default=on]],
  ,
  [
    PKG_CHECK_MODULES(SSL, openssl, ,[
    	# check SSL if it part of the installation
	SSL_CFLAGS=""
	SSL_LIBS="-lssl -lcrypto"
	AC_CHECK_HEADERS(openssl/ssl.h, , AC_MSG_ERROR([cannot find openssl/ssl.h]) )
	LIBS_save=$LIBS
	LIBS="$LIBS $SSL_LIBS"
	AC_TRY_LINK(
	    [ #include <openssl/ssl.h> ],
	    [ SSL_library_init(); ],
	    ,
	    AC_MSG_ERROR(Cannot link with ssl libraries)
	)
	LIBS=$LIBS_save
	AC_SUBST(SSL_CFLAGS)
	AC_SUBST(SSL_LIBS)
    ])
    AC_DEFINE(STARTTLS, 1, Use starttls command support.)
    AC_DEFINE(HAVE_OPENSSL, 1, OpenSSL present.)
  ]
)

AC_ARG_WITH(krb5,[  --with-krb5	use Kerberos V libs for authentication (broken)], [CHECK_KRB(5)] )
AC_ARG_WITH(krb4,[  --with-krb4	use Kerberos IV libs for authentication (broken)], [CHECK_KRB(4)] )
AC_ARG_ENABLE(auth,[  --enable-auth	turn on authentication support [[default=off]] (broken)] )
AC_ARG_ENABLE(enc,[  --enable-enc	turn on encryption support [[default=off]] (broken)] )


if test x$enable_enc = xyes ; then
	AC_DEFINE(ENCRYPTION, 1, Use encryption support.)
	AC_DEFINE(DES_ENCRYPTION, 1, Use DES encryption support.)
	enable_auth=yes
fi

if test x$enable_auth = xyes ; then
    if test x$with_krb5 != xyes -a x$with_krb4 != xyes ; then
    	with_krb5=yes
    fi
    AC_DEFINE(AUTHENTICATION, 1, Use authentication support.)
fi

if test x$with_krb5 = xyes ; then
	CHECK_KRB(5)
	AC_DEFINE(KRB5, 1, [Use kerberos V authentication.])
fi

if test x$with_krb4 = xyes ; then
	CHECK_KRB(4)
	AC_DEFINE(KRB4, 1, [Use kerberos IV authentication.])
fi


# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.
# also uses ttytype
AC_CHECK_LIB([ncurses], [setupterm])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_GETPGRP
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([alarm gethostbyname gethostname memmove memset select setenv socket strcasecmp strchr strdup strerror strncasecmp strrchr])

AC_CONFIG_FILES([Makefile
                 m4/Makefile
                 misc/Makefile])
AC_OUTPUT
