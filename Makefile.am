noinst_PROGRAMS =	table-ldap

table_ldap_SOURCES =	table_ldap.c aldap.c ber.c dict.c log.c table_stdio.c util.c

LDADD =			$(LIBOBJS)

smtpdir =		${prefix}/libexec/smtpd

install-exec-local: $(noinst_PROGRAMS)
	$(MKDIR_P) $(DESTDIR)$(smtpdir)
	$(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) $(noinst_PROGRAMS) $(DESTDIR)$(smtpdir)
