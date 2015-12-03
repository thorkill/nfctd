AUTOMAKE_OPTIONS = foreign
SUBDIRS = src include

EXTRA_DIST = LICENSE configure.ac nfctd.service.in config/nfctd.conf.dist config/collectd-nfctd.types.db doc/RRZN-MIB doc/uncrustify.cfg

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/nfctd
	$(INSTALL_DATA) $(srcdir)/config/nfctd.conf.dist $(DESTDIR)$(sysconfdir)/nfctd/nfctd.conf.dist;
	$(INSTALL_DATA) $(srcdir)/config/collectd-nfctd.types.db $(DESTDIR)$(sysconfdir)/nfctd/collectd-nfctd.types.db;

	$(mkinstalldirs) $(DESTDIR)/lib/systemd/system/;
	$(INSTALL_DATA) $(srcdir)/nfctd.service $(DESTDIR)/lib/systemd/system/;

	if [ ! -e $(DESTDIR)$(sysconfdir)/nfctd/nfctd.conf ]; then \
		$(INSTALL_DATA) $(srcdir)/config/nfctd.conf.dist $(DESTDIR)$(sysconfdir)/nfctd/nfctd.conf; \
	fi

	if [ ! -e $(DESTDIR)$(sysconfdir)/nfctd/collectd-nfctd.types.db ]; then \
		$(INSTALL_DATA) $(srcdir)/config/collectd-nfctd.types.db $(DESTDIR)$(sysconfdir)/nfctd/collectd-nfctd.types.db; \
	fi
