noinst_PROGRAMS =	table-ldap

table_ldap_SOURCES =	table_ldap.c aldap.c ber.c dict.c log.c table_api.c util.c

LDADD =			$(LIBOBJS)

dist_man5_MANS =	table-ldap.5

EXTRA_DIST =		aldap.h ber.h compat.h config.h.in \
			dict.h log.h table_api.h util.h

smtpdir =		${prefix}/libexec/smtpd

install-exec-local: $(noinst_PROGRAMS)
	$(MKDIR_P) $(DESTDIR)$(smtpdir)
	$(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) $(noinst_PROGRAMS) $(DESTDIR)$(smtpdir)

uninstall-local:
	rm $(DESTDIR)$(smtpdir)/$(noinst_PROGRAMS)

