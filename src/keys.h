void *
 fixkey(char *key, unsigned int *len, char* keymode, int keysize,
      int quiet, int stream_flag, void *salt, int salt_size, int enc_mode);
word32* shrink_password(char *passwd, int *keysize, int lenofpasswd);
int mcrypt_gen_key ( char* keymode, void* keyword, int keysize, void* salt, int saltsize, unsigned char* password, int plen);
int _which_algo ( char* keymode);
int _mcrypt_pgp_conv_keymode( const char* keymode, keygenid* km, hashid *halg);
