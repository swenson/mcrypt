/*
 *    Copyright (C) 1998,1999,2000 Nikos Mavroyanopoulos
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

/* $Id: xmalloc.c,v 1.2 2007/11/07 17:10:23 nmav Exp $ */

#include <defines.h>
#include <extra.h>

static char rcsid[] = "$Id: xmalloc.c,v 1.2 2007/11/07 17:10:23 nmav Exp $";

/* memory allocation */
void *
 _mcrypt_malloc(size_t size)
{
	char *x;

	if (size==0) return NULL;
	
	x = malloc(size);
	if (x != NULL) {
		return x;
	} else {
		fprintf(stderr, _("Cannot allocate memory\n"));
		exit(-1);
	}
/* Not really needed */
	return x;
}

void *
 _mcrypt_calloc(size_t nmemb, size_t size)
{
	char *x;

	if (size==0) return NULL;
	
	x = calloc(nmemb, size);
	if (x != NULL) {
		return x;
	} else {
		fprintf(stderr, _("Cannot allocate memory\n"));
		exit(-1);
	}
/* Not really needed */
	return x;

}

void *
 _mcrypt_realloc(void *ptr, size_t size)
{
	char *x;

	x = realloc(ptr, size);
	if (x != NULL) {
		return x;
	} else {
		fprintf(stderr, _("Cannot allocate memory\n"));
		exit(-1);
	}
/* Not really needed */
	return x;

}



void *
 _secure_mcrypt_malloc(size_t size)
{
	char *x;

	x = malloc(size);
	if (x != NULL) {
		return x;
	} else {
		fprintf(stderr, _("Cannot allocate memory\n"));
		exit(-1);
	}
/* Not really needed */
	return x;
}

void *
 _secure_mcrypt_calloc(size_t nmemb, size_t size)
{
	char *x;

	x = calloc(nmemb, size);
	if (x != NULL) {
		return x;
	} else {
		fprintf(stderr, _("Cannot allocate memory\n"));
		exit(-1);
	}
/* Not really needed */
	return x;

}

void *
 _secure_mcrypt_realloc(void *ptr, size_t size)
{
	char *x;

	x = realloc(ptr, size);
	if (x != NULL) {
		return x;
	} else {
		fprintf(stderr, _("Cannot allocate memory\n"));
		exit(-1);
	}
/* Not really needed */
	return x;

}

void _mcrypt_free( void* ptr) {
	free(ptr);
}

void _secure_mcrypt_free( void* ptr, int size) {
	Bzero(ptr, size);
	free(ptr);
}

char* _mcrypt_strdup( const char* str) {
char* ret;

	ret = strdup( str);
	if (ret==NULL) {
		fprintf(stderr, _("Cannot allocate memory\n"));
		exit(-1);
	}
	return ret;
}

