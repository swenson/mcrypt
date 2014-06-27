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

/* $Id: keys.c,v 1.2 2007/11/07 17:10:20 nmav Exp $ */

#ifndef DEFINES_H
#define DEFINES_H
#include <defines.h>
#endif
#include <extra.h>
#include <xmalloc.h>
#include <errors.h>
#include <ufc_crypt.h>

static char rcsid[] = "$Id: keys.c,v 1.2 2007/11/07 17:10:20 nmav Exp $";

int _mcrypt_pgp_conv_keymode( const char* keymode, keygenid* km, hashid *halg) {
	if (strcasecmp(keymode, "s2k-simple-md5")==0) {
		*km=KEYGEN_S2K_SIMPLE; 
		*halg=MHASH_MD5;
	} else if (strcasecmp(keymode, "s2k-simple-sha1")==0) {
		*km=KEYGEN_S2K_SIMPLE; 
		*halg=MHASH_SHA1;
	} else if (strcasecmp(keymode, "s2k-simple-ripemd")==0) {
		*km=KEYGEN_S2K_SIMPLE; 
		*halg=MHASH_RIPEMD160;
	} else if (strcasecmp(keymode, "s2k-salted-md5")==0) {
		*km=KEYGEN_S2K_SALTED; 
		*halg=MHASH_MD5;
	} else if (strcasecmp(keymode, "s2k-salted-sha1")==0) {
		*km=KEYGEN_S2K_SALTED; 
		*halg=MHASH_SHA1;
	} else if (strcasecmp(keymode, "s2k-salted-ripemd")==0) {
		*km=KEYGEN_S2K_SALTED; 
		*halg=MHASH_RIPEMD160;
	} else if (strcasecmp(keymode, "s2k-isalted-md5")==0) {
		*km=KEYGEN_S2K_ISALTED; 
		*halg=MHASH_MD5;
	} else if (strcasecmp(keymode, "s2k-isalted-sha1")==0) {
		*km=KEYGEN_S2K_ISALTED; 
		*halg=MHASH_SHA1;
	} else if (strcasecmp(keymode, "s2k-isalted-ripemd")==0) {
		*km=KEYGEN_S2K_ISALTED; 
		*halg=MHASH_RIPEMD160;
	} else return -1;

	return 0;
}

int mcrypt_gen_key ( char* keymode, void* keyword, int keysize, 
	void* salt, int saltsize, byte* password, int plen) {

	KEYGEN data;
	keygenid id=0;
	hashid algo=0;
	int icrypt=0;

	if (strcasecmp(keymode, "scrypt")==0) icrypt=1;	
	if (strcasecmp(keymode, "asis")==0) id=KEYGEN_ASIS;
	if (strcasecmp(keymode, "hex")==0) id=KEYGEN_HEX;
	if (strcasecmp(keymode, "pkdes")==0) id=KEYGEN_PKDES;
	if (strcasecmp(keymode, "mcrypt-sha1")==0) {id=KEYGEN_MCRYPT; algo=MHASH_SHA1;}
	if (strcasecmp(keymode, "mcrypt-md5")==0) {id=KEYGEN_ASIS; algo=MHASH_MD5;}
	_mcrypt_pgp_conv_keymode( keymode, &id, &algo);

	if (icrypt==0) {
		data.hash_algorithm[0] = algo;
		data.count = 0;
		data.salt = salt;
		data.salt_size = saltsize;
		return mhash_keygen_ext( id, data, keyword, keysize, password, plen);
	} else {
		return gen_crypt( keyword, keysize, password, plen);
	}
}



/* fixkey takes the input key (or NULL if it wasn't given) and converts it
 */
void *
 fixkey(char *key, unsigned int *len, char* keymode, int keysize,
     int quiet, int stream_flag, void *salt, int salt_size, int enc_mode)
{
	int i;
#ifdef DEBUG
	unsigned char* psalt=salt;
#endif
	char *tmp;
	char *keyword;
	char *tmpkey;


        tmpkey= _mcrypt_calloc(1, MAX_KEY_LEN);
	keyword = _mcrypt_calloc(1, keysize);

	if (key == NULL) {	/* key was not specified in the command line */
		tmp = get_password( enc_mode, len);
		if (tmp == NULL)
			return NULL;

		if (*len > MAX_KEY_LEN)
			*len = MAX_KEY_LEN;
		memmove(tmpkey, tmp, *len);

		Bzero(tmp, strlen(tmp));
	} else {		/* Key was given on the command line */
		if (*len > MAX_KEY_LEN)
			*len = MAX_KEY_LEN;
		memmove(tmpkey, key, *len);
	}

		/* Generate key by hashing the passphrase */
		if (salt_size==0) salt=NULL;
		i = mcrypt_gen_key( keymode, keyword, keysize, salt, salt_size,
					(void *) tmpkey, *len);
		/* unexpected error in libmhash 
		 */
		if (i < 0) err_quit(_("Key transformation failed.\n"));
		Bzero(tmpkey, *len);	/* key is not bzero'd because it may be used again */

		*len = keysize;

/* Do not ever define it */
/* It prints the key in the plain */

#ifdef DEBUG
	fprintf(stderr, "keylen: %d\n", keysize);

	fprintf(stderr, "key: ");
	for (i = 0; i < *len; i++) {
		fprintf(stderr, "%.2x.", (unsigned char) keyword[i]);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "salt: ");
	if (salt!=NULL) {
	for (i = 0; i < salt_size; i++) {
		fprintf(stderr, "%.2x.", psalt[i]);
	}
	fprintf(stderr, "\n");
	}
#endif

	Bzero( tmpkey, MAX_KEY_LEN);
	
	return keyword;

}

int _which_algo ( char* keymode) {

	if (strcasecmp(keymode, "asis")==0) return 0;
	if (strcasecmp(keymode, "scrypt")==0) return 0;
	if (strcasecmp(keymode, "hex")==0) return 0;
	if (strcasecmp(keymode, "pkdes")==0) return 0;
	if (strcasecmp(keymode, "mcrypt-sha1")==0) return 0;
	if (strcasecmp(keymode, "mcrypt-md5")==0) return 0;
	if (strcasecmp(keymode, "s2k-simple-md5")==0) return 0;
	if (strcasecmp(keymode, "s2k-simple-ripemd")==0) return 0;
	if (strcasecmp(keymode, "s2k-simple-sha1")==0) return 0;
	if (strcasecmp(keymode, "s2k-salted-md5")==0) return 0;
	if (strcasecmp(keymode, "s2k-salted-sha1")==0) return 0;
	if (strcasecmp(keymode, "s2k-salted-ripemd")==0) return 0;
	if (strcasecmp(keymode, "s2k-isalted-md5")==0) return 0;
	if (strcasecmp(keymode, "s2k-isalted-sha1")==0) return 0;
	if (strcasecmp(keymode, "s2k-isalted-ripemd")==0) return 0;

	return -1;
}
