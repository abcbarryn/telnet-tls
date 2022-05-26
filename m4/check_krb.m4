AC_DEFUN([CHECK_KRB],
[
  	AC_PATH_PROG(KRB[$1]_CONFIG,krb[$1]-config)
  	if test -z "$KRB[$1]_CONFIG" ; then
  		AC_MSG_FAILURE(Kerberos [$1] not found)
  	fi
  	KRB5_CFLAGS=`$KRB[$1]_CONFIG --cflags`
  	KRB5_LIBS=`$KRB[$1]_CONFIG --libs`
  	CFLAGS="$CFLAGS $KRB[$1]_CFLAGS"
  	LIBS="$LIBS $KRB[$1]_LIBS"
])
