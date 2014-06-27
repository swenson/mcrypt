
/* type == 0 or 1 */
void mcrypt_randomize( void* buf, int buf_size, int type);
void mcrypt_init_random( void);
void mcrypt_deinit_random( void);

#ifndef HAVE_DEV_RANDOM

void init_random(void);
void deinit_random(void);

int
gather_random( int level);

void hash_given_data( void* data, size_t data_size);

#endif
