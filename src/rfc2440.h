/* rfc2440.h - OpenPGP message format
 *   Copyright (C) 2002, 2007 Timo Schulz
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef RFC2440_H
#define RFC2440_H

/* PGP error constants. */
enum pgp_error_t {
    PGP_SUCCESS = 0,
    PGP_ERR_PKT = 1,
    PGP_ERR_GENERAL = 2,
    PGP_ERR_FILE = 3
};  

/* OpenPGP packet types. */
enum pkt_packettype_t {
    PKT_SYMKEY_ENC = 3,
    PKT_ONEPASS_SIG = 4,
    PKT_COMPRESSED = 8,
    PKT_ENCRYPTED = 9,
    PKT_PLAINTEXT = 11,
};

/* OpenPGP S2K types. */
enum pgp_s2k_type_t {
    OPENPGP_S2K_SIMPLE = 0,
    OPENPGP_S2K_SALTED = 1,
    OPENPGP_S2K_ISALTED = 3
};

/* OpenPGP hash identifiers. */
enum {
    OPENPGP_MD_MD5 = 1,
    OPENPGP_MD_SHA1 = 2,
    OPENPGP_MD_RMD160 = 3
};

/* OpenPGP cipher identifiers. */
enum {
    OPENPGP_ENC_3DES = 2,
    OPENPGP_ENC_CAST5 = 3,
    OPENPGP_ENC_BLOWFISH = 4,
    OPENPGP_ENC_AES128 = 7,
    OPENPGP_ENC_AES192 = 8,
    OPENPGP_ENC_AES256 = 9,
    OPENPGP_ENC_TWOFISH = 10
};


typedef struct ustring_s {
    size_t len;
    unsigned char *d;
} *USTRING;

/* Context to hold the data encryption key. */
typedef struct {
    struct {
        int mode;
        unsigned char algo;
        unsigned char salt[8];
        unsigned int count;
    } s2k;
    MCRYPT hd;
    unsigned char key[32];
    int keylen;
    int blocklen;
    char* algo;
} DEK;


/* Interface to the OpenPGP functions. */
int pgp_encrypt_file(const char *infile, const char *outfile, char *pass);
int pgp_decrypt_file(const char *infile, const char *outfile, char *pass);

#endif /*RFC2440_H*/
