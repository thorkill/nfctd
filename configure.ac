dnl Process this file with autoconf to create configure.
AC_PREREQ([2.68])
AC_INIT([nfctd], [0.1.0], [lesniak@dcsec.uni-hannover.de])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl kernel style compile messages
dnl m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_MAKE_SET
AC_PROG_RANLIB

case "$host" in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac


AC_CONFIG_SRCDIR([src/nfctd.c])
AC_CONFIG_HEADERS([config.h])

#CFLAGS="-g -O2"

dnl Dependencies
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdlib.h string.h])

dnl Check for inet_ntop
AC_CHECK_FUNCS(inet_ntop)
# Checks for library functions.
AC_CHECK_FUNCS([malloc memset])
AC_FUNC_MALLOC


# Checks for programs.

AC_MSG_CHECKING([for net-snmp-config])
AC_MSG_RESULT([...])
AC_SUBST([LIBNETSNMPAGENT_LDFLAGS])
AC_CHECK_PROG([LIBNETSNMPAGENT_LDFLAGS],[net-snmp-config],[`net-snmp-config --netsnmp-agent-libs`],[none])
AC_SUBST([LIBNETSNMP_CFLAGS])
AC_CHECK_PROG([LIBNETSNMP_CFLAGS],[net-snmp-config],[`net-snmp-config --cflags`],[none])
if test x"${LIBNETSNMPAGENT_LDFLAGS}" = "xnone"; then
	AC_MSG_CHECKING([for net-snmp-config])
	AC_MSG_ERROR([net-snmp-config not found, please install the development package of net-snmp])
else
	AC_MSG_CHECKING([for net-snmp-config])
	AC_MSG_RESULT([found])
fi


# Checks for libraries.
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 1.0.0])
AC_CHECK_LIB([netfilter_conntrack], [nfct_open])
AC_CHECK_LIB([ev], [ev_run])
AC_CHECK_LIB([pcap], [bpf_filter])

AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

dnl Output the makefile
AC_CONFIG_FILES([Makefile src/Makefile include/Makefile nfctd.service])
AC_OUTPUT

