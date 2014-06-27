/*
 *    Copyright (C) 2002 Nikos Mavroyanopoulos
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


#ifndef DEFINES_H
#define DEFINES_H
#include <defines.h>
#endif
#include <mcrypt_int.h>
#include <extra.h>
#include <rfc2440.h>

/* Wrapper functions for the rfc2440.c interface.
 */

int total_bytes; /* holds the bytes processed by rfc2440.c
                  * on encryption or decryption.
                  */

int pgp_encrypt_wrap( const char *infile, const char *outfile, char *pass ) {
char* _pass;
int len, ret;

	total_bytes = 0;

	if (pass==NULL) _pass = get_password( ENCRYPT, &len);
	else _pass = pass;

	if (_pass==NULL) return -1;

	_mcrypt_start_timer();
	ret = pgp_encrypt_file( infile, outfile, _pass);
	_mcrypt_end_timer();

	print_enc_info( infile, outfile);

        if (ret == 0) _mcrypt_time_show_stats( total_bytes);

	return ret;
}

int pgp_decrypt_wrap( const char *infile, const char *outfile, char *pass ) {
char* _pass;
int len, ret;

	total_bytes = 0;

	if (pass==NULL) _pass = get_password( DECRYPT, &len);
	else _pass = pass;

	if (_pass==NULL) return -1;

	_mcrypt_start_timer();
	ret = pgp_decrypt_file( infile, outfile, _pass);
	_mcrypt_end_timer();

	print_enc_info( infile, outfile);

        if (ret==0) _mcrypt_time_show_stats( total_bytes);

	return ret;
}

