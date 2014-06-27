## Process this file with automake to produce Makefile.in

EXTRA_DIST = config.rpath  INSTALL.generic THANKS NEWS
SUBDIRS = doc src po
install-exec-hook:
	-$(RM) -f $(DESTDIR)$(bindir)/mdecrypt
	$(LN_S) mcrypt $(DESTDIR)$(bindir)/mdecrypt
uninstall-local:
	-$(RM) -f $(DESTDIR)$(bindir)/mdecrypt

ChangeLog:
	cvs2cl --utc --fsf -t -S --prune
 
ACLOCAL_AMFLAGS = -I m4
