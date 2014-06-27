#define MAX_KEY_LEN 513

#define rotl32(x,n)   (((x) << ((word32)(n))) | ((x) >> (32 - (word32)(n))))
#define rotr32(x,n)   (((x) >> ((word32)(n))) | ((x) << (32 - (word32)(n))))
#define rotl16(x,n)   (((x) << ((word16)(n))) | ((x) >> (16 - (word16)(n))))
#define rotr16(x,n)   (((x) >> ((word16)(n))) | ((x) << (16 - (word16)(n))))
#define byteswap32(x)     ((rotl32(x, 8) & 0x00ff00ff) | (rotr32(x, 8) & 0xff00ff00))
#define byteswap16(x)  ((rotl16(x, 8) & 0x00ff) | (rotr16(x, 8) & 0xff00))

char * get_password( int mode, unsigned int *len);
int show_mode(int ende, int stype,int smode,char *output,int bitmode);
char** read_key_file(char * file, int* num);
char *get_cfile(int uid, char*);
void Bzero(void *s, size_t n);
void mcrypt_tolow(char *str, int size);

char *my_getpass();
int check_file_head(FILE *fstream, char *algorithm, char* mode, char* keymode, int *keysize, void* salt, int* salt_size);
void* read_iv(FILE *fstream, int ivsize);
int write_file_head(FILE * filedes, char* algorithm, char* mode, char* keymode, int* keysize, void *salt, int salt_size);
int write_iv(FILE * filedes, void* IV, int ivsize);

void cleanUp();
void shandler(int signal);

#ifdef HAVE_STAT
#ifdef HAVE_UTIME
void copyDate ( char *srcName, char *dstName );
# endif
int is_normal_file(char *filename);
#endif
int check_file(char * filename);

unsigned int Hex_To_Int(char ch);
void Read_Key_Hex_String(char *str);

int ask_overwrite(char *, char * file);
void test_file_headers( char* file);
void print_enc_info( const char*, const char*);

void _mcrypt_start_timer(void);
void _mcrypt_end_timer(void);
void _mcrypt_time_show_stats( size_t file_sum);
