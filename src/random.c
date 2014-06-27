/*
 *    Copyright (C) 1998,1999,2000,2007 Nikos Mavroyanopoulos
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *                               
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

/* $Id: random.c,v 1.2 2007/11/07 17:10:22 nmav Exp $ */

#ifndef DEFINES_H
#define DEFINES_H
#include <defines.h>
#endif
#include <errors.h>
#include <random.h>

static char rcsid[] = "$Id: random.c,v 1.2 2007/11/07 17:10:22 nmav Exp $";

extern int real_random_flag; /* mcrypt.c */

#ifdef HAVE_DEV_RANDOM

static int fd0;
static int fd1;

/* When need of many data is required */

void mcrypt_init_random( void)
{
	fd0 = open(NAME_OF_DEV_URANDOM, O_RDONLY);
	if (fd0 == -1) {
		perror(NAME_OF_DEV_URANDOM);
		exit(-1);
	}

	fd1 = open(NAME_OF_DEV_RANDOM, O_RDONLY);
	if (fd1 == -1) {
		perror(NAME_OF_DEV_RANDOM);
		exit(-1);
	}
	return;
}

void mcrypt_deinit_random( void) {
	close(fd0);
	close(fd1);
}

#else

void mcrypt_init_random( void) {
	init_random();
}

void mcrypt_deinit_random( void) {
	deinit_random();
}

#endif				/* HAVE_DEV_RANDOM */


#ifndef HAVE_DEV_RANDOM
extern char *algorithms_directory;
extern char *modes_directory;
static byte rnd_pool[20];

/* Here we hold a pool of 20 bytes. When we get anything random
 * we hash it and then xor the 20 bytes output with the pool.
 * After that the pool data are expanded and stored into the output 
 * buffer.
 */

/* This function will hash the given data and xor the res
 * with them. This should be ok if res_size <= 20
 */
#define MAX_COUNT 5
void hash_given_data( void* data, size_t data_size) {
MHASH td;
byte _res[20];
int i;

	td = mhash_init( MHASH_SHA1);
	if (td==MHASH_FAILED) {
		err_quit(_("mhash_init() failed."));
	}

	/* also hash the pool
	 */
	mhash( td, rnd_pool, 20);
	
	mhash(td, data, data_size);

	mhash_deinit( td, _res);

	/* addition may do as well as xor
	 */
	for(i=0;i<20;i++) rnd_pool[i] ^= _res[i];


	/* Step 1 was completed. The pool was updated.
	 */
	 
}
#endif /* !HAVE_DEV_RANDOM */

void mcrypt_randomize( void* _buf, int buf_size, int type) {
#ifdef HAVE_DEV_RANDOM
unsigned char *buf = _buf;
int _fd;
	if (type==0) _fd = fd0;
	else _fd = fd1;

	if (read( _fd, buf, buf_size)==-1) {
		err_quit(_("Error while reading random data\n"));
	}

#else /* no /dev/random */
int level;
static int pool_inited;
static MCRYPT ed;

	if ( !pool_inited) {
		if (real_random_flag!=0) level = 2;
		else level = 1;
		gather_random( level);
		pool_inited = 1;

		 /* Expansion step.
		  * Pool data are expanded as:
		  * pool is set as an arcfour key. The arcfour algorithm
		  * is then used to encrypt the given data, 
		  * to generate a pseudorandom sequence.
		  */
	  
		ed = mcrypt_module_open( "arcfour", algorithms_directory,
			"stream", modes_directory); 
		if (ed==MCRYPT_FAILED)
			err_quit(_("Mcrypt failed to open module.\n"));

		if (mcrypt_generic_init( ed, rnd_pool, 20, NULL) < 0) {
			err_quit(_("Mcrypt failed to initialize cipher.\n"));
		}

	}

	mcrypt_generic( ed, _buf, buf_size);

	return;

#endif
}
