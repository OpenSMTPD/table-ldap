AC_INIT([table-ldap], [1.0], [bugs@opensmtpd.org])
AC_CONFIG_AUX_DIR(etc)
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AC_CONFIG_LIBOBJ_DIR(openbsd-compat)
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

AC_REPLACE_FUNCS([ \
	asprintf \
	getprogname \
	err \
	strlcat \
	strlcpy \
	strsep \
	strtonum \
])

AC_SEARCH_LIBS([evbuffer_pullup], [event_core], [], [
	AC_MSG_ERROR([requires libevent])
])

AC_SEARCH_LIBS([tls_init], [tls], [], [
	AC_MSG_ERROR([requires libtls])
])

AM_CPPFLAGS="-I$srcdir/openbsd-compat"

AC_CHECK_HEADER([sys/tree.h], [], [
	AM_CPPFLAGS="$AM_CPPFLAGS -I$srcdir/openbsd-compat/tree"
])

AC_SUBST([AM_CPPFLAGS])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
