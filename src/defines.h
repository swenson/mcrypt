#ifndef IDEFINES_H
# define IDEFINES_H

#include <config.h>

/* #define DEBUG Don't even think defining it:) */

#include <mhash.h>
#include <mcrypt.h>

#if MCRYPT_API_VERSION < 20000222
# error "Your mcrypt.h header file is older than the library"
#endif

#ifdef STDC_HEADERS
# include <string.h>
# include <stdlib.h>
# include <stdio.h>
#endif

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#include <time.h>

#ifndef FUNCTIONS_H
# define FUNCTIONS_H
# include "functions.h"
#endif

#ifdef BZIP2
# define ZIP
#else
# ifdef GZIP
#  define ZIP
# endif
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
  

#include <gettext.h>
#ifdef ENABLE_NLS
# define _(String) gettext (String) 
#else
# define _(String) (String) 
#endif

#ifdef HAVE_UTIME_H
# include <utime.h>
#endif

#ifdef WIN32
# undef HAVE_UTIME
#endif

/* for open */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifndef HAVE_FSEEKO
# define fseeko fseek
#endif

#ifndef HAVE_OFF_T
 typedef long off_t;
#endif

/* defines */
#define SALT_SIZE 20

#define TRUE 1
#define FALSE 0

#define HASH_SIZE 10

#define BUFFER_SIZE 1024
#define KEYMODE_SIZE 20
#define ALGORITHM_SIZE 15
#define MODE_SIZE 10
#define IV_SIZE 64

# define DEFAULT_ALGORITHM "rijndael-128" /* The AES winner */

#define DEFAULT_MODE "cbc"
#define DEFAULT_PGP_MODE "ncfb"
#define DEFAULT_PGP_ALGO "cast-128"
#define DEFAULT_KEYMODE "mcrypt-sha1"
#define DEFAULT_PGP_KEYMODE "s2k-isalted-sha1"
#define HASH_ALGORITHM "sha1"

#define ENCRYPT 0
#define DECRYPT 1

#if SIZEOF_UNSIGNED_LONG_INT == 4
 typedef unsigned long word32;
 typedef signed long sword32;
#elif SIZEOF_UNSIGNED_INT == 4
 typedef unsigned int word32;
 typedef signed int sword32;
#else
 typedef unsigned int word32; /* default */
 typedef signed int sword32;
#endif

#if SIZEOF_UNSIGNED_INT == 2
 typedef unsigned int word16;
#elif SIZEOF_UNSIGNED_SHORT_INT == 2
 typedef unsigned short word16;
#else 
 typedef unsigned short int word16; /* default */
 typedef signed short int sword16;
#endif

#if SIZEOF_UNSIGNED_CHAR == 1
 typedef unsigned char byte; 
#else
 typedef unsigned char byte;
#endif


#ifndef HAVE_STRLCPY
# define strlcpy(x, y, s) strncpy(x, y, s); x[s-1]='\0'
#endif

#ifndef HAVE_MEMMOVE
# ifdef HAVE_BCOPY
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# else
#  error "Neither memmove nor bcopy exists on your system."
# endif
#endif

/*extern char *getpass();*/
extern char *crypt(); /* libufc */

#if HAVE_TERMIOS_H
# include <termios.h>
# define STTY(fd, termio) tcsetattr(fd, TCSANOW, termio)
# define GTTY(fd, termio) tcgetattr(fd, termio)
# define TERMIO struct termios
# define USE_TERMIOS
#elif HAVE_TERMIO_H
# include <sys/ioctl.h>
# include <termio.h>
# define STTY(fd, termio) ioctl(fd, TCSETA, termio)
# define GTTY(fd, termio) ioctl(fd, TCGETA, termio)
# define TEMRIO struct termio
# define USE_TERMIO
#elif HAVE_SGTTY_H
# include <sgtty.h>
# define STTY(fd, termio) stty(fd, termio)
# define GTTY(fd, termio) gtty(fd, termio)
# define TERMIO struct sgttyb
# define USE_SGTTY
#endif

#ifdef USE_DMALLOC
# include <dmalloc.h>
#endif

#endif /* IDEFINES_H */

