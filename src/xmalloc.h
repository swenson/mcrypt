#ifndef USE_DMALLOC

void *_mcrypt_malloc(size_t size);
void *_mcrypt_calloc(size_t nmemb, size_t size);
void *_mcrypt_realloc(void *ptr, size_t size);
void * _secure_mcrypt_malloc(size_t size);
void * _secure_mcrypt_calloc(size_t nmemb, size_t size);
void * _secure_mcrypt_realloc(void *ptr, size_t size);
void _mcrypt_free( void* ptr);
void _secure_mcrypt_free( void* ptr, int size);
char* _mcrypt_strdup( const char* str);
#else

# define _mcrypt_malloc malloc
# define _mcrypt_calloc calloc
# define _mcrypt_realloc realloc
# define _secure_mcrypt_malloc malloc
# define _secure_mcrypt_calloc calloc
# define _secure_mcrypt_realloc realloc
# define _mcrypt_free free
# define _secure_mcrypt_free(x,y) free(x)
# define _mcrypt_strdup strdup

#endif
