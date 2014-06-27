/* Defines for the environment variables */

#define MCRYPT_ALGO "MCRYPT_ALGO"
#define MCRYPT_KEY "MCRYPT_KEY"
#define MCRYPT_MODE "MCRYPT_MODE"
#define MCRYPT_KEY_MODE "MCRYPT_KEY_MODE"

int check_env();
char ** get_env_key();
char * get_env_algo();
char * get_env_mode();
char * get_env_bit_mode();

