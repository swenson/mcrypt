/* mcrypt.c */
int encrypt_ucrypt(char *fromfile,char *tofile, char *key);

int encrypt_general(char* algorithm, char *fromfile,char *tofile,char *key);
int decrypt_general(char* algorithm, char *fromfile,char *tofile,char *key);

int check_algo(char *chain); /* input is the algorithms name... output the
                              * algorithm's number
                              */
int check_mode(char *chain);
int check_hash_algo(char *chain);

void rol_buf(void * buffer, int buffersize,void * value);

void mcrypt_version();
void mcrypt_license();
void usage(void);
