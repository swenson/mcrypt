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

/* $Id: environ.c,v 1.2 2007/11/07 17:10:19 nmav Exp $ */

#ifndef DEFINES_H
#define DEFINES_H
#include <defines.h>
#endif
#include <environ.h>
#include <extra.h>
#include <xmalloc.h>

static char rcsid[] = "$Id: environ.c,v 1.2 2007/11/07 17:10:19 nmav Exp $";

int check_env()
{

	if (getenv(MCRYPT_KEY) != NULL
	    || getenv(MCRYPT_ALGO) != NULL
	    || getenv(MCRYPT_MODE) != NULL)
		return TRUE;	/* ok */
	return FALSE;

}

char **
 get_env_key()
{
	char **tmp;

	if (getenv(MCRYPT_KEY) != NULL) {
		tmp = _mcrypt_malloc(sizeof(char *));
		tmp[0] = getenv(MCRYPT_KEY);
		return tmp;
	} else {
		return NULL;
	}

}

char *
 get_env_algo()
{

	return getenv(MCRYPT_ALGO);

}

char *
 get_env_mode()
{

	return getenv(MCRYPT_MODE);

}

char *get_env_bit_mode()
{

	return getenv(MCRYPT_KEY_MODE);

}
