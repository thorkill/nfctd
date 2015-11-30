AUTOMAKE_OPTIONS = foreign
SUBDIRS = src

EXTRA_DIST = configure.ac config/nfctd.conf.dist

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/nfctd
	$(INSTALL_DATA) $(srcdir)/config/nfctd.conf.dist $(DESTDIR)$(sysconfdir)/nfctd/nfctd.conf.dist;
	$(INSTALL_DATA) $(srcdir)/config/collectd-nfctd.types.db $(DESTDIR)$(sysconfdir)/nfctd/collectd-nfctd.types.db;

	$(INSTALL_DATA) $(srcdir)/nfctd.service /lib/systemd/system/;
	if [ ! -e $(DESTDIR)$(sysconfdir)/nfctd/nfctd.conf ]; then \
		$(INSTALL_DATA) $(srcdir)/config/nfctd.conf.dist $(DESTDIR)$(sysconfdir)/nfctd/nfctd.conf; \
	fi

	if [ ! -e $(DESTDIR)$(sysconfdir)/nfctd/collectd-nfctd.types.db ]; then \
		$(INSTALL_DATA) $(srcdir)/config/collectd-nfctd.types.db $(DESTDIR)$(sysconfdir)/nfctd/collectd-nfctd.types.db; \
	fi
