unsigned int m_setbit(unsigned int which, unsigned int fullnum, unsigned int what);
#define m_getbit(n, v)    (((unsigned int)(v) >> (unsigned)(n)) & 1)
#define i_setbit(n, v)    ((unsigned int)(v) | (1U << (unsigned)(n)))
#define i_unsetbit(n, v)    ((unsigned int)(v) & ~(1U << (unsigned)(n)))
