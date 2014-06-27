/* rfc2440.c - OpenPGP message format
 *   Copyright (C) 2002, 2007 Timo Schulz
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

#include <defines.h>
#include <random.h>
#include <time.h>
#include <assert.h>
#ifdef HAVE_LIBZ
#include <zlib.h>
#endif
#include <stdio.h>
#include <malloc.h>

#include "xmalloc.h"
#include "keys.h"
#include "errors.h"
#include "rfc2440.h"
#include "defines.h"

#ifndef _mcrypt_calloc
#define _mcrypt_calloc calloc
#endif

/*-- mcrypt.c --*/
extern char *algorithm;
extern int keysize;
extern char* keymode;
extern char* mode;
extern int openpgp_z;
extern int real_random_flag;
/*--------------*/

extern int total_bytes; /* openpgp.c */

/* typedef short cuts for common primitive data types. */
typedef unsigned int uint32;
typedef unsigned char uchar;

#define S2K_DEFAULT_COUNT 96

#ifndef DIM /* helper to figure out the amount of elements. */
#define DIM(x) (sizeof (x) / sizeof (x)[0])
#endif

typedef struct packet_s {
    unsigned blockmode:1;
    unsigned old:1;
} PACKET;


/* FIXME: the 'mmap' interface could be a problem for larger
          files. In general it would be better to provide a
          more flexible solutions with smaller buffers. */


static USTRING
make_ustring(const uchar *buffer, size_t length)
{
    USTRING a;
    
    a = _mcrypt_calloc(1, sizeof *a + length);
    a->len = length;
    a->d = (void*)a + sizeof *a;
    memset(a->d, 1, length);
    if (buffer != NULL)
        memcpy(a->d, buffer, length);
    return a;
}

static USTRING
realloc_ustring(const USTRING src, size_t length)
{
    USTRING a;
    size_t len;
    
    len = length;
    if (src != NULL)
	len += src->len;
    a = _mcrypt_calloc(1,  sizeof *a + len);
    a->len = len;
    a->d = (void*)a + sizeof *a;
    memset(a->d, 1, len);
    if (src != NULL) {
	memcpy(a->d, src->d, src->len);
	free(src);
    }
    return a;
}

static uchar*
file_to_buf(const char *file, off_t offset, size_t *ret_len )
{
    struct stat statbuf;
    uchar *buf;
    FILE *fp;
    size_t len;

    /* Return NULL if the file cannot be stat or has a length of zero. */
    if (stat(file, &statbuf) == -1 ||
	statbuf.st_size == 0)
        return NULL;
    
    len = statbuf.st_size;
    fp = fopen(file, "rb");
    if (fp == NULL)
        return NULL;
    buf = _mcrypt_calloc(1,  len);
    fseeko(fp, offset, SEEK_SET);
    fread(buf, 1, len, fp);
    fclose(fp);
    *ret_len = len - offset;
    return buf;
}

static void
_mcrypt_sync(MCRYPT hd, uchar *rndpref, int blocklen)
{
    uchar sync[19];

    if (blocklen != 8 && blocklen != 16)
        return;
    sync[0] = 0;
    memcpy(sync + 1, rndpref + 2, blocklen);
    mcrypt_enc_set_state(hd, sync, blocklen + 1);
}


static int
_mcrypt_encrypt(MCRYPT hd, uchar *out, size_t outlen,
		uchar *in, size_t inlen)
{
    if (!in)
        return mcrypt_generic(hd, out, outlen);
    if (outlen < inlen)
        return -1;
    memcpy(out, in, inlen);
    mcrypt_generic(hd, out, inlen);    
    return 0;
}

static int
_mcrypt_decrypt(MCRYPT hd, uchar *out, size_t outlen,
		uchar *in, size_t inlen)
{
    if (!in)
        return mdecrypt_generic(hd, out, outlen);
    if (outlen < inlen)
        return -1;
    memcpy(out, in, inlen);
    mdecrypt_generic(hd, out, inlen);        
    return 0;
}


static char*
_mhash_keymode2str(keygenid ki, hashid hi)
{
    static char ret[512];
    
    ret[0] = 0;
    if (ki == KEYGEN_S2K_SIMPLE)
        strcat(ret, "s2k-simple-");
    else if (ki == KEYGEN_S2K_SALTED)
        strcat(ret, "s2k-salted-");
    else if (ki == KEYGEN_S2K_ISALTED)
        strcat(ret, "s2k-isalted-");
          
    if (hi == MHASH_SHA1)
        strcat(ret, "sha1");
    else if (hi == MHASH_MD5)
        strcat(ret, "md5");
    else if (hi == MHASH_RIPEMD160)
        strcat(ret, "ripemd");
    else if (hi == MHASH_SHA256)
	strcat(ret, "sha256");                
    return ret;
}

/* Convert the OpenPGP type ID to the local mhash ID. */
static int
_mhash_keygen(uchar algid)
{
    switch (algid) {
    case OPENPGP_S2K_SIMPLE: return KEYGEN_S2K_SIMPLE;
    case OPENPGP_S2K_SALTED: return KEYGEN_S2K_SALTED;
    case OPENPGP_S2K_ISALTED: return KEYGEN_S2K_ISALTED;
    }    
    return KEYGEN_S2K_ISALTED; /* return default keygen mode. */
}

int
_mhash_keygen_to_rfc2440(int algo)
{
    switch (algo) {
    case KEYGEN_S2K_SIMPLE: return OPENPGP_S2K_SIMPLE;
    case KEYGEN_S2K_SALTED: return OPENPGP_S2K_SALTED;
    case KEYGEN_S2K_ISALTED: return OPENPGP_S2K_ISALTED;
    }
    return OPENPGP_S2K_ISALTED;
}

static int
_mhash_algo(uchar algid)
{
    switch ( algid ) {
    case OPENPGP_MD_MD5: return MHASH_MD5;
    case OPENPGP_MD_SHA1: return MHASH_SHA1;
    case OPENPGP_MD_RMD160: return MHASH_RIPEMD160;
    }
    return MHASH_SHA1;
}

static int
_mhash_algo_to_rfc2440(int algo)
{
    switch (algo) {
    case MHASH_MD5: return OPENPGP_MD_MD5;
    case MHASH_SHA1: return OPENPGP_MD_SHA1;
    case MHASH_RIPEMD160: return OPENPGP_MD_RMD160;
    }
    return OPENPGP_MD_SHA1;
}


static char*
_mcrypt_algid_to_algo(uchar algid)
{
    switch (algid) {
    case OPENPGP_ENC_3DES: 
	keysize = 24;
	return "tripledes";
        
    case OPENPGP_ENC_CAST5: 
	keysize = 16;
	return "cast-128";
        
    case OPENPGP_ENC_BLOWFISH: 
	keysize = 16;
	return "blowfish";
        
    case OPENPGP_ENC_AES128: 
	keysize = 16;
	return "rijndael-128";
	
    case OPENPGP_ENC_AES192: 
	keysize = 24;
	return "rijndael-128";
        
    case OPENPGP_ENC_AES256: 
	keysize = 32;
	return "rijndael-128";
        
    case OPENPGP_ENC_TWOFISH: 
	keysize = 32;
	return "twofish";
    }
    
    /* default cipher is CAST5. */
    keysize = 16;
    return "cast-128";
}

/* convert mcrypt specific ID to an OpenPGP ID. */
static uchar
_mcrypt_algo_to_algid(char *algo)
{
    if  (!strcmp(algo, "tripledes"))
        return OPENPGP_ENC_3DES;
    else if (!strcmp(algo, "cast-128"))
        return OPENPGP_ENC_CAST5;
    else if (!strcmp(algo, "blowfish"))
        return OPENPGP_ENC_BLOWFISH;
    else if (!strcmp(algo, "rijndael-128") && keysize == 16)
        return OPENPGP_ENC_AES128;
    else if ( !strcmp(algo, "rijndael-128") && keysize == 24)
        return OPENPGP_ENC_AES192;
    else if ( !strcmp(algo, "rijndael-128") && keysize == 32)
        return OPENPGP_ENC_AES256;
    else if ( !strcmp(algo, "twofish"))
        return OPENPGP_ENC_TWOFISH;

    return OPENPGP_ENC_AES128;
}

static char*
pgp_get_algo(char *algo)
{
    /* Return default cipher algorithm. */
    if (!algo)
        return "cast-128";

    /* make sure we only use OpenPGP compatible algorithms */
    if (!strcmp(algo, "tripledes") ||
	!strcmp(algo, "cast-128") ||
	!strcmp(algo, "blowfish") ||
	!strcmp(algo, "rijndael-128") ||
	!strcmp(algo, "twofish"))
        return algo;

    fprintf(stderr,
	    _("Algorithm %s is not available in OpenPGP encryption.\n"),
	    algo);
    fprintf(stderr, _("%s will be used instead.\n"), DEFAULT_PGP_ALGO);
    return DEFAULT_PGP_ALGO;
}


static uint32
get_pkt_tag(const uchar *buf, PACKET *pkt)
{
    uint32 tag = -1;
    
    assert(buf);
    if (!(buf[0] & 0x80))
        return -1; /* invalid */
    if (buf[0] & 0x40) { /* new style */
        tag = buf[0] & 0x3f;
        if (pkt) 
	    pkt->old = 0;
    }
    else { /* old style */
        tag = (buf[0] & 0x3c) >> 2;
        if (pkt)
	    pkt->old = 1;
    }
    return tag;
}


static uint32
length_len(const uint32 len, PACKET *pkt)
{
    uint32 ret = 0;

    if (pkt && pkt->blockmode)
        return 1;
    else if (pkt && pkt->old) {
        if (len < 0xff)
            ret = 1;
        else if (len < 0xffff)
            ret = 2;
        else if (len < 0xffffffff)
            ret = 4;
    }
    else {    
        if (len < 192)
            ret = 1;
        else if (len < 8384)
            ret = 2;
        else
            ret = 5;
    }
    return ret;
}


static void
length_encode(uint32 len, uchar *lenbuf, uchar *lensize)
{
    assert(len > 0);
    
    if (len < 192) {
        lenbuf[0] = len;
	*lensize = 1;
    }
    else if (len < 8384) {
        len -= 192;        
        lenbuf[0] = len / 256 + 192;
        lenbuf[1] = len % 256;
	*lensize = 2;
    }
    else {
        lenbuf[0] = 255;
        lenbuf[1] = len >> 24;
        lenbuf[2] = len >> 16;
        lenbuf[3] = len >>  8;
        lenbuf[4] = len;
	*lensize = 5;
    }
}


static uint32
length_decode(const uchar *buf, int pos, PACKET *pkt)
{
    uint32 len = 0;
    
    assert (buf != NULL);
    assert (pos >= 0);

    if (buf[pos] < 192)
        len = buf[pos];
    else if (buf[pos] >= 192 && buf[pos] <= 223) {
        len = (buf[pos] - 192) << 8;
        len += (buf[pos+1] + 192);
    }
    else if (buf[pos] == 255) {
        len += (buf[pos+1] << 24);
        len += (buf[pos+2] << 16);
        len += (buf[pos+3] << 8);
        len += buf[pos+4];
    }
    else {
        len = 1 << (buf[pos]);
        if (pkt) 
	    pkt->blockmode = 1;
    }   
    return len;
}

static void
header_decode(const uchar *buf, uint32 *tag, uint32 *len,
	      uint32 *headlen, PACKET *pkt)
{
    assert (buf != NULL);

    *tag = get_pkt_tag(buf, pkt);
    if (buf[0] & 0x40) {
        *len = length_decode( buf, 1, pkt );
        *headlen = 1 + length_len( *len, pkt );
    }
    else {
        if ((buf[0] & 0x03) == 0) {
            *len = buf[1];
            *headlen = 2;
        }
        else if ((buf[0] & 0x03) == 1) {
            *len = (buf[1] << 8) | buf[2];
            *headlen = 3;
        }
        else if ((buf[0] & 0x03) == 2) {
            *len = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
            *headlen = 5;
        }
        else if ((buf[0] & 0x03) == 3) {
            *len = 0;
            *headlen = 1;
        }
    }
}

int
plaintext_decode(const USTRING pt, USTRING *result)
{
    uint32 headlen = 0, tag = 0, offset = 0;
    PACKET pkt;
    USTRING t;

    memset( &pkt, 0, sizeof(pkt));

    assert(pt->len > 0);
    header_decode(pt->d, &tag, &headlen, &offset, &pkt);
    if (tag != PKT_PLAINTEXT)
        return PGP_ERR_PKT;

    if (pt->len < 8) /* wrong len */
        return PGP_ERR_PKT;
    if (!pkt.blockmode && (pt->len-1-length_len(headlen, &pkt)) != headlen)
        return PGP_ERR_PKT; /* malformed */
    if (pt->d[offset] != 0x62 && pt->d[offset] != 0x74)
        return PGP_ERR_PKT;
    offset++;

    /* we ignore the file name but need to skip past it if its present */
    if (pt->d[offset] > 0)
        offset += pt->d[offset];
    offset++; /* file name length */
    offset += 4; /* timestamp */

    t = make_ustring( pt->d+offset, pt->len-offset);
    *result = t;

    return PGP_SUCCESS;
}


USTRING
plaintext_encode(const USTRING dat)
{
    USTRING result = NULL, newdat = NULL;
    uint32 pos = 0;
    uchar lenbuf[5], lensize = 0;
    time_t t;

    assert(dat->len > 0);
    result = make_ustring( NULL,  2 * dat->len); /* xxx */
    newdat = (USTRING)dat;
    result->d[pos++] = (0x80 | 0x40 | PKT_PLAINTEXT);

    /* 1 byte data type, 4 bytes timestamp, 1 byte non-file-name */
    length_encode(dat->len + 6, lenbuf, &lensize);
    memcpy(result->d + pos, lenbuf, lensize);
    pos += lensize;
    
    t = time(NULL); /* time of creation. */
    result->d[pos++] = 0x62; /* binary */
    result->d[pos++] = 0; /* no file name */    
    result->d[pos++] = t >> 24;
    result->d[pos++] = t >> 16;
    result->d[pos++] = t >>  8;
    result->d[pos++] = t;

    memcpy(result->d + pos, newdat->d, newdat->len);
    result->len = pos + newdat->len;
    return result;
}

void
dek_free(DEK *d)
{
    if (!d)
	return;
    mcrypt_generic_deinit(d->hd);
    mcrypt_module_close(d->hd);
    free(d);
}


static int
pgp_get_keysize(const char *algo)
{
    int keylen = keysize;

    /* OpenPGP uses fixed key sizes which means we need to
       change the size for variable ciphers. */
    if (!strcmp(algo, "twofish" ))
        keylen = 32;
    if (!strcmp(algo, "blowfish"))
        keylen = 16;
    if (!strcmp(algo, "cast-128"))
        keylen = 16;
    keysize = keylen; /* set the global key size to this */
    return keylen;
}


void
dek_load(DEK *d, char *pass)
{
    KEYGEN keygen_data;
    char* mode = DEFAULT_PGP_MODE;
    int ret;
    
    d->keylen = pgp_get_keysize(d->algo);
    keygen_data.hash_algorithm[0] = d->s2k.algo;
    keygen_data.count = d->s2k.count;
    keygen_data.salt = d->s2k.salt;
    keygen_data.salt_size = 8;

    d->blocklen = mcrypt_module_get_algo_block_size(d->algo, NULL);
    ret = mhash_keygen_ext(d->s2k.mode, keygen_data, d->key, 
			   DIM (d->key), pass, strlen(pass));
    if (ret < 0)
    	err_quit(_("mhash_keygen_ext() failed.\n"));
    d->hd = mcrypt_module_open(d->algo, NULL, mode, NULL);
    if (d->hd == MCRYPT_FAILED)
    	err_quit(_("Could not open module\n"));
}


DEK*
dek_create(char* algo, char *pass)
{
    DEK *d;
    KEYGEN keygen_data;
    char* mode = DEFAULT_PGP_MODE;
    keygenid mh_keymode;
    hashid mh_alg;
    int ret;
    
    d = _mcrypt_calloc(1, sizeof *d);
    d->algo = algo;
    d->keylen = pgp_get_keysize(algo);
    d->blocklen = mcrypt_module_get_algo_block_size(algo, NULL);
    
    algorithm = d->algo;
    keysize = d->keylen;
    
    /* There are two ways for symmetric encryption.
       1. To derrive the session key directly from the passphrase
       2. Use a random session key and it encrypt it with a derrived
         key from the passphrase.
       For the sake of simplicity, we always use method 1. */    
    if (_mcrypt_pgp_conv_keymode(keymode, &mh_keymode, &mh_alg) < 0) {
        char tmp[255];
	
        snprintf(tmp, DIM (tmp)-1, _("OpenPGP: Unsupported key mode %s\n"),
                  keymode);
    	err_quit(tmp);
    }
    
    d->s2k.mode = mh_keymode;
    d->s2k.algo = mh_alg;
    d->s2k.count = S2K_DEFAULT_COUNT;

    keygen_data.hash_algorithm[0] = mh_alg;
    keygen_data.count = S2K_DEFAULT_COUNT;
    keygen_data.salt = d->s2k.salt;
    keygen_data.salt_size = 8;

    mcrypt_randomize(d->s2k.salt, 8, 0);
    ret = mhash_keygen_ext(mh_keymode, keygen_data, d->key,
			   DIM (d->key), pass, strlen(pass));
    if (ret < 0)
    	err_quit(_("mhash_keygen_ext() failed.\n"));
    d->hd = mcrypt_module_open(algo, NULL, mode, NULL);
    if (d->hd == MCRYPT_FAILED)
    	err_quit(_("Could not open module\n"));
    return d;
}


int
symkey_enc_decode(const USTRING dat, DEK **ret_dek)
{
    DEK *d;
    int tag = 0, headlen = 0, offset = 0;

    assert(dat->len > 0);
    
    header_decode(dat->d, &tag, &headlen, &offset, NULL);
    if (tag != PKT_SYMKEY_ENC)
        return PGP_ERR_PKT;
    if (headlen < 3)
        return PGP_ERR_PKT;
    if (dat->d[offset++] != 4)
        return PGP_ERR_PKT; /* invalid version */
    
    d = _mcrypt_calloc(1,  sizeof *d);
    d->algo = _mcrypt_algid_to_algo(dat->d[offset++]);
    d->s2k.mode = _mhash_keygen(dat->d[offset++]);
    d->s2k.algo = _mhash_algo(dat->d[offset++]);
    if (d->s2k.mode != KEYGEN_S2K_SIMPLE) {
        memcpy(d->s2k.salt, dat->d + offset, 8);
        offset += 8;
    }
    if (d->s2k.mode == KEYGEN_S2K_ISALTED)
        d->s2k.count = dat->d[offset++];
    *ret_dek = d;

    /* in order to print the proper algorithm later. */
    algorithm = d->algo;
    keymode = _mhash_keymode2str(d->s2k.mode, d->s2k.algo);
    mode = DEFAULT_PGP_MODE;  /* no other options */

    return 0;
}


USTRING
symkey_enc_encode(const DEK *dek)
{
    USTRING result;
    int pos = 0;
    uchar buf[16];

    assert(dek->keylen > 0);

    buf[pos++] = (0x80 | 0x40 | PKT_SYMKEY_ENC);
    buf[pos++] = 4; /* length */
    buf[pos++] = 4; /* version */
    buf[pos++] = _mcrypt_algo_to_algid(dek->algo);
    buf[pos++] = _mhash_keygen_to_rfc2440(dek->s2k.mode);
    buf[pos++] = _mhash_algo_to_rfc2440(dek->s2k.algo);
    if (dek->s2k.mode != KEYGEN_S2K_SIMPLE) {
        memcpy(buf+pos, dek->s2k.salt, 8);
        pos += 8;
        buf[1] += 8;
    }
    if (dek->s2k.mode == KEYGEN_S2K_ISALTED) {
        buf[pos++] = dek->s2k.count;
        buf[1] += 1;
    }
    result = make_ustring(buf, pos);
    result->len = pos;
    return result;
}


USTRING
read_partial(const uchar *buf, size_t blen, size_t pktlen)
{
    USTRING dat;
    uchar data[2048];
    int pos = 0, partial = 1;
    PACKET pkt;

    memset( &pkt, 0, sizeof(pkt));

    dat = make_ustring(NULL, blen);
    while (pktlen > 0) {
        /*fprintf( stderr, "ptklen=%d pos=%d blen=%d partial=%d llen=%d\n",
                 pktlen, pos, blen, partial, length_len( pktlen, &pkt) );*/
        while (pktlen > 2048 && pos < blen) {
            memcpy(data, buf, 2048);
            memcpy(dat->d + pos, data, 2048);
            pos += 2048;
            buf += 2048; pktlen -= 2048;
        }
        if (pktlen > 0 && pos < blen) {
            memcpy(data, buf, pktlen);
            memcpy(dat->d + pos, data, pktlen);
            pos += pktlen;
            buf += pktlen; pktlen -= pktlen;
        }
        if (!partial)
            break;
        else {
            memset(&pkt, 0, sizeof (pkt));
            pktlen = length_decode(buf, 0, &pkt);
            buf += length_len(pktlen, &pkt);
            partial = pkt.blockmode;
        }
    }
    dat->len = pos;
    return dat;
}

int
encrypted_decode(const DEK *dek, const USTRING dat, USTRING *result)
{
    int rc, nprefix;
    uint32 tag = 0, headlen = 0, offset = 0;
    uchar rndprefix[18], encprefix[18];
    PACKET pkt;
    USTRING t = NULL, p = NULL;

    memset(&pkt, 0, sizeof(pkt));
    
    assert(dat->len > 0);
    header_decode(dat->d, &tag, &headlen, &offset, &pkt);
    
    if (tag != PKT_ENCRYPTED)
        return PGP_ERR_PKT;
    if (dat->len < dek->blocklen + 3)
        return PGP_ERR_PKT; /* wrong len */
    if (!pkt.blockmode && (dat->len-1-length_len(headlen, &pkt)) != headlen)
        return PGP_ERR_PKT; /* moderately malformed */

    rc = mcrypt_generic_init(dek->hd, (uchar *)&dek->key, dek->keylen, NULL);
    if (rc < 0)
    	err_quit(_("mcrypt_generic_init() failed\n"));

    nprefix = dek->blocklen;
    memcpy(encprefix, dat->d + offset, nprefix + 2);
    _mcrypt_decrypt(dek->hd, rndprefix, nprefix + 2,
		    dat->d + offset, nprefix + 2);
    offset += (nprefix + 2);

    /* Note that we don't decrypt the whole thing at once;
       if 7 != 9 or 8 != 10 then we immediately stop */
    if (rndprefix[nprefix] != rndprefix[nprefix-2] ||
	rndprefix[nprefix+1] != rndprefix[nprefix-1]) {
        err_warn(_("decryption: wrong key.\n"));
        return PGP_ERR_GENERAL;
    }
    _mcrypt_sync(dek->hd, encprefix, dek->blocklen);

    if (!pkt.blockmode) {
        t = make_ustring( dat->d+offset,  dat->len - offset); /* xxx */

        _mcrypt_decrypt(dek->hd, t->d, t->len, NULL, 0);
    }
    else {
        p = read_partial(dat->d + (offset - (nprefix+2)),
			 dat->len - (offset - (nprefix+2)), headlen);
        if (!p || !p->len) {
            *result = NULL;
            return PGP_ERR_GENERAL;
        }
        t = make_ustring(p->d + (nprefix+2), p->len - (nprefix+2));
        _mcrypt_decrypt(dek->hd, t->d, t->len, NULL, 0);
        free(p); p=NULL;
    }
    *result = t;
    return 0;
}


USTRING
encrypted_encode(const USTRING pt, const DEK *dek)
{
    USTRING ct, result;
    uchar rndpref[18], lenbuf[5], lensize;
    int pos, rc;

    assert(pt->len > 0);

    rc = mcrypt_generic_init(dek->hd, (uchar *)&dek->key, dek->keylen, NULL);
    if (rc < 0)
    	err_quit( _("mcrypt_generic_init() failed\n") );

    mcrypt_randomize(rndpref, dek->blocklen, real_random_flag);
    rndpref[dek->blocklen] = rndpref[dek->blocklen - 2];
    rndpref[dek->blocklen + 1] = rndpref[dek->blocklen - 1];
    _mcrypt_encrypt(dek->hd, rndpref, dek->blocklen + 2, NULL, 0);
    _mcrypt_sync(dek->hd, rndpref, dek->blocklen);

    ct = make_ustring( rndpref,   2 * pt->len); /* xxx */
    pos = dek->blocklen + 2;
    
    _mcrypt_encrypt(dek->hd, ct->d + pos, pt->len, pt->d, pt->len);
    ct->len = (pos += pt->len);
    pos = 0;

    result = make_ustring( NULL,  ct->len + 8); /* xxx */
    result->d[pos++] = (0x80 | 0x40 | PKT_ENCRYPTED);
    length_encode(ct->len, lenbuf, &lensize);
    memcpy(result->d + pos, lenbuf, lensize);
    pos += lensize;
    
    memcpy(result->d + pos, ct->d, ct->len);
    result->len = ct->len + pos;
    free(ct);
    
    return result; 
}


static int
do_compress(int algo, int flush, uchar *inbuf, size_t insize,
	    USTRING *ret_out)
{
#ifdef HAVE_LIBZ
    uchar buf[4096];
    int pos = 0, len = 0;
    int zrc = 0;
    z_stream *zs = NULL;
    USTRING out = NULL;
    
    zs = _mcrypt_calloc( 1,  sizeof *zs );
    zrc = (algo == 1)? deflateInit2(zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
				    -13, openpgp_z, Z_DEFAULT_STRATEGY):
    deflateInit(zs, Z_DEFAULT_COMPRESSION);
    if (zrc)
        goto leave;
    
    zs->next_in = inbuf;
    zs->avail_in = insize;

    do {
        zs->next_out = buf;
        zs->avail_out = sizeof(buf);
        zrc = deflate( zs, flush );
        if ( zrc == Z_STREAM_END ) {
            deflateEnd( zs );
            if ( zs->avail_out ) {
                len = sizeof(buf) - zs->avail_out;
                out = realloc_ustring( out, len );
                memcpy( out->d + pos, buf, len );
                pos += len;
                break;
            }
        }
        if ( zrc == Z_OK ) {
            len = sizeof(buf) - zs->avail_out;
            out = realloc_ustring( out, len );
            memcpy( out->d + pos, buf, len );
            pos += len;
        }        
        
        if ( zrc ) {
            if ( zs->msg )
                fprintf( stderr, _("zlib error `%s'.\n"), zs->msg );
            fprintf( stderr, _("compress: deflate returned %d.\n"), zrc );
        }            
    } while ( zs->avail_out == 0 );
    
leave:
    *ret_out = out;
    free( zs );
    if ( zrc == Z_OK || zrc == Z_STREAM_END )
        zrc = 0;
    return zrc;
#else
    return 0;
#endif
} /* do_compress */

USTRING
compressed_encode( const USTRING dat, int algo )
{
#ifdef HAVE_LIBZ
    USTRING result = NULL, z = NULL;
    int rc = 0;

    assert( dat->len );
    rc = do_compress( algo, Z_NO_FLUSH, dat->d, dat->len, &z );
    if ( !rc )
        rc = do_compress( algo, Z_FINISH, dat->d, dat->len, &z );
    if ( rc )
        goto leave;

    result = make_ustring( NULL,  z->len + 8); /* xxx */
    result->len = z->len + 3;
    result->d[0] = (0x80 | 0x40 | PKT_COMPRESSED);
    result->d[1] = 0;
    result->d[2] = algo;
    memcpy( result->d + 3, z->d, z->len );

leave:
    free( z );
    return result;
#else
    return NULL;
#endif
} /* compressed_encode */

static int
do_uncompress( int algo, uchar *inbuf, size_t insize, USTRING *ret_out )
{
#ifdef HAVE_LIBZ
    USTRING out = NULL;
    z_stream *zs = NULL;
    uchar buf[4096];
    int pos = 0, len = 0;
    int zrc = 0;
    
    zs = _mcrypt_calloc( 1,  sizeof *zs );
    zrc = ( algo == 1 )? inflateInit2( zs, -13 ) : inflateInit( zs );
    if ( zrc )
        goto leave;

    zs->next_in = inbuf;
    zs->avail_in = insize;

    do {
        zs->next_out = buf;
        zs->avail_out = sizeof(buf);

        zrc = inflate( zs, Z_SYNC_FLUSH );
        if ( zrc == Z_STREAM_END ) {
            inflateEnd( zs );
            if ( zs->avail_out ) {
                len = sizeof(buf) - zs->avail_out;
                out = realloc_ustring( out, len );
                memcpy( out->d + pos, buf, len );
                out->len = (pos += len);
                /*fprintf( stderr, "DBG: end len=%d pos=%d\n", len, pos );*/
            }
            break;
        }
        if ( zrc == Z_OK ) {
            len = sizeof(buf) - zs->avail_out;
            out = realloc_ustring( out, len );
            memcpy( out->d + pos, buf, len );
            out->len = (pos += len);
            /*fprintf( stderr, "DBG: ok len=%d pos=%d\n", len, pos );*/
        }
        if ( zrc ) {            
            if ( zs->msg )
                fprintf( stderr, _("zlib error `%s'.\n"), zs->msg );
            fprintf( stderr, _("uncompress: inflate returned %d.\n"), zrc );
            break;
        }
    } while ( 1 );

leave:
    *ret_out = out;
    free( zs );
    if ( zrc == Z_OK || zrc == Z_STREAM_END )
        zrc = 0;
    return zrc;
#else
    return 0;
#endif
} /* do_uncompress */

int
compressed_decode( const USTRING zip, USTRING *result )
{
#ifdef HAVE_LIBZ
    uint32 tag = 0, headlen = 0, offset = 0;
    USTRING t = NULL;
    int rc = 0;

    assert( zip->len );
    header_decode( zip->d, &tag, &headlen, &offset, NULL );

    if ( tag != PKT_COMPRESSED )
        return PGP_ERR_PKT;
    if ( zip->d[offset] != 1 && zip->d[offset] != 2 )
        return PGP_ERR_PKT;

    err_info( _("Will decompress input file.\n") );
    rc = do_uncompress( zip->d[offset], zip->d + offset + 1,
                        zip->len - offset - 1, &t );
    *result = t;
    
    return rc;
#else
    return 0;
#endif
} /* compressed_decode */


int
pgp_encrypt_file(const char *infile, const char *outfile, char *pass)
{
    USTRING t = NULL, pt = NULL, sym = NULL, enc = NULL, zip = NULL;
    DEK *dek = NULL;
    FILE *fp = NULL;
    uchar *buf = NULL, tmp[16*1024];
    size_t len = 0, nread = 0;
    int tag=0;
    
    if (!infile || *infile == '-') {
        while (!feof(stdin)) {
            nread = fread(tmp, 1, DIM (tmp), stdin);
	    if (nread > 0) {
                t = realloc_ustring (t, nread);
                memcpy (t->d + len, tmp, nread);
            }
            len += nread;
        }
        fp = stdout;
    }
    else {
        fp = fopen(outfile, "wb");
        if (fp == NULL)
            return PGP_ERR_FILE;
        buf = file_to_buf(infile, 0, &len);
        if (!buf) {
	    fclose (fp);
            return PGP_ERR_FILE;
	}
        t = make_ustring(buf, len);
    }
    tag = get_pkt_tag(t->d, NULL);
    free(buf);
    dek = dek_create(pgp_get_algo(algorithm), pass);
    sym = symkey_enc_encode(dek);
    fwrite(sym->d, 1, sym->len, fp);
    free(sym);
    total_bytes += t->len; /* increase input bytes */
    
    pt = plaintext_encode(t);
    free(t);
#ifdef HAVE_LIBZ
    if (openpgp_z > 0 && tag == -1 && pt && len > 32) {
        err_info( _("Output file will be compressed.\n") );
        zip = compressed_encode(pt, 1);
        free(pt);
    }
    else zip = pt;
#else
    zip = pt;
#endif
    if (zip) {
        enc = encrypted_encode(zip, dek);
        free(zip);
    }
    if (enc) {
        fwrite(enc->d, 1, enc->len, fp);
        free(enc);
    }
    dek_free(dek);
    if (fp != stdout)
	fclose(fp);
    else
	fflush (fp);
    return 0;
}

int
pgp_decrypt_file(const char *infile, const char *outfile, char *pass)
{
    USTRING r = NULL, dat = NULL, pt = NULL, result = NULL;
    uchar *buf = NULL, tmp[16*1024];
    const uchar *p;
    DEK *dek = NULL;
    PACKET pkt;
    uint32 off = 0, tag = 0, len = 0;
    size_t flen = 0, nread;
    int rc = 0;
    FILE *fp;

    memset(&pkt, 0, sizeof(pkt));

    if (!infile || *infile == '-') {
        while (!feof(stdin)) {
            nread = fread(tmp, 1, DIM (tmp), stdin);
            if (nread) {
                buf = realloc(buf, flen + nread);
                memcpy(buf + flen, tmp, nread);
            }
            flen += nread;
        }
    }
    else {
        buf = file_to_buf(infile, 0, &flen);
        if (!buf)
	    return PGP_ERR_FILE;
    }
    total_bytes = flen;
    p = buf;
    while (flen > 0) {
        memset(&pkt, 0, sizeof (pkt));
        header_decode(p, &tag, &len, &off, &pkt);
        switch (tag) {
        case PKT_SYMKEY_ENC:
            r = make_ustring(p, len + off);
            rc = symkey_enc_decode(r, &dek);
	    free (r);
            /*fprintf(stderr, "symkey_enc_decode=%d\n", rc);*/
	    if (rc) {
		free (buf);
		return rc;
	    }
	    dek_load(dek, pass);
            break;

        case PKT_ENCRYPTED:
            r = make_ustring(p, flen);
            rc = encrypted_decode(dek, r, &dat);
            /*fprintf(stderr, "encrypted=%d\n", rc);*/
            free(r);
	    if (rc) {
		free (buf);
		return rc;
	    }
            flen = 0; /* automatic EOF */
            break;
                
        default:
            /*fprintf(stderr, "tag=%d\n", tag);*/
	    free (buf);
            return PGP_ERR_PKT;
        }
        if (flen > 0) {
            p += (len + off);
            flen -= (len + off);
        }
    }
    free(buf);
    dek_free(dek);
    if (!dat)
	return PGP_ERR_FILE;

    if (get_pkt_tag(dat->d, NULL) == PKT_COMPRESSED) {
	rc = compressed_decode(dat, &pt);
	/*fprintf(stderr,"compressed=%d\n",rc);*/
	free(dat);
	if (rc)
	    return rc;
    }
    else
	pt = dat;
    
    if (get_pkt_tag(pt->d, NULL) != PKT_PLAINTEXT) {
	err_warn(_("Unsupported OpenPGP packet!\n"));
	free (pt);
    }
    rc = plaintext_decode(pt, &result);
    free (pt);
    /*fprintf(stderr,"plaintext=%d\n", rc);*/
    if (rc)
	return rc;

    if (!outfile)
	fp = stdout;
    else {
	fp = fopen(outfile, "wb");
	if (fp == NULL) {
	    free(result);
	    return PGP_ERR_FILE;
	}
    }
    fwrite(result->d, 1, result->len, fp);
    free(result);
    if (outfile)
	fclose(fp);
    else
	fflush (fp);
    return 0;
}

