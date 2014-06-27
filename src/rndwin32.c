/*
 * Copyright (C) 2002,2007 Nikos Mavroyanopoulos
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

static char rcsid[] = "$Id: rndwin32.c,v 1.3 2007/11/07 17:14:58 nmav Exp $";

#include <config.h>

#ifdef WIN32

#include <errors.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <random.h>

/* WARNING: These functions were not tested at ALL.
 */

static HCRYPTPROV hProv = NULL;

void init_random(void) 
{
	if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT|CRYPT_VERIFYCONTEXT)) {
		err_quit("Error calling CryptAcquireContext()");
	}
}

void deinit_random( void) 
{

	if(!CryptReleaseContext(hProv, 0)) {
		err_quit("Error calling CryptReleaseContext()");
	}

}

#define RND_DATA 128
int gather_random( int level) 
{
char buf[RND_DATA];

	if(!CryptGenRandom(hProv, (DWORD)RND_DATA, buf)) {
		fprintf(stderr, "CryptGenRandom: error %d\n", GetLastError());
		err_quit("Error calling CryptGenRandom()");
	}
	
	hash_given_data( buf, RND_DATA);

	return 0;
}

#endif
