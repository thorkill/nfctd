
AM_CFLAGS = -std=c99 -Wall -Werror=cpp -I../include/ @LIBNETSNMP_CFLAGS@
AM_LDFLAGS = @LIBNETSNMPAGENT_LDFLAGS@

bin_PROGRAMS = nfctd
nfctd_SOURCES = nfctd-snmp.c lcfg_static.c \
    nfctd.c
