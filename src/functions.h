
/* Bzero is now in libmcrypt */

#ifndef SIGFUNC
# define SIGFUNC
 typedef void Sigfunc(int);
#endif

Sigfunc *Signal( int signo, Sigfunc *func);
