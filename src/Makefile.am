
#AM_CFLAGS = -Wall -Werror -Werror=cpp -I../include/ `net-snmp-config --cflags` -fdiagnostics-color=always
AM_CFLAGS = -Wall -Werror -Werror=cpp -I../include/ \
-DNETSNMP_ENABLE_IPV6 -fno-strict-aliasing -march=x86-64 \
-mtune=generic -O2 -pipe -fstack-protector-strong \
--param=ssp-buffer-size=4 -Ulinux -Dlinux=linux \
-D_REENTRANT -D_GNU_SOURCE -fwrapv -fno-strict-aliasing \
-pipe -fstack-protector-strong \
-I/usr/local/include -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 \
-I/usr/lib/perl5/core_perl/CORE -I/usr/include/libnl3 -I. \
-I/usr/include -fdiagnostics-color=always

AM_LDFLAGS = -lnetfilter_conntrack -ldl \
-Wl,-O1,--sort-common,--as-needed,-z,relro -L/usr/lib -lnetsnmp -lcrypto -lnl-3 -lm \
-lnetsnmpmibs -lpci -ldl -lnetsnmpagent -Wl,-E -Wl,-rpath,/usr/lib/perl5/core_perl/CORE \
-lev -lpcap

bin_PROGRAMS = nfctd
nfctd_SOURCES = nfctd-snmp.c lcfg_static.c \
    nfctd.c
