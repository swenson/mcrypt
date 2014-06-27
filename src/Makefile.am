## Process this file with automake to produce Makefile.in

INCLUDES = -DLOCALEDIR=\"$(localedir)\" -I../intl
bin_PROGRAMS = mcrypt
EXTRA_DIST = crypt defines.h errors.h gaa.h keys.h random.h \
       extra.h getpass.h environ.h ufc_crypt.h rfc2440.h \
       functions.h mcrypt_int.h xmalloc.h gaaout.c mcrypt.gaa bits.h \
       openpgp.h popen.h gettext.h

mcrypt_SOURCES = extra.c mcrypt.c keys.c random.c rndunix.c \
          xmalloc.c functions.c errors.c bits.c openpgp.c rndwin32.c \
          environ.c getpass.c ufc_crypt.c popen.c classic.c rfc2440.c
localedir = $(datadir)/locale
mcrypt_LDADD = gaaout.o @LIBINTL@ 
gaaout.o: gaaout.c
	$(CC) -o gaaout.o -c gaaout.c $(INCLUDES) $(CFLAGS) $(CPPFLAGS) -I. -I..
gaaout.c: mcrypt.gaa
	gaa -o gaaout.c -i gaa.h mcrypt.gaa
