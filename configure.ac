dnl Process this file with autoconf to create configure.
AC_PREREQ([2.69])
AC_INIT([nfctd], [0.0.1], [lesniak@dcsec.uni-hannover.de])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

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

#CFLAGS="-g -O2"

dnl Dependencies
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 1.0.0])
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdlib.h string.h])

dnl Check for inet_ntop
AC_CHECK_FUNCS(inet_ntop)



AC_CONFIG_SRCDIR([src/nfctd.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([mnl], [mnl_nlmsg_size])
AC_CHECK_LIB([netfilter_conntrack], [nfct_catch])

AC_CHECK_LIB([netsnmp], [netsnmp_create_handler_registration])
AC_CHECK_LIB([crypto], [rand])
AC_CHECK_LIB([m], [main])

AC_CHECK_LIB([netsnmpmibs], [main])
AC_CHECK_LIB([nl-3], [main])
AC_CHECK_LIB([pci], [main])
AC_CHECK_LIB([netsnmpagent], [main])

AC_CHECK_LIB([netfilter_conntrack], [main])
AC_CHECK_LIB([mln], [main])
AC_CHECK_LIB([ev], [main])
AC_CHECK_LIB([pcap], [main])

AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset select])

dnl Output the makefile
AC_CONFIG_FILES([Makefile src/Makefile include/Makefile nfctd.service])
AC_OUTPUT

