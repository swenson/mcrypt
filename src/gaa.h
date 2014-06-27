
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 112 "mcrypt.gaa"
	char **input;
#line 111 "mcrypt.gaa"
	int size;
#line 101 "mcrypt.gaa"
	int quiet;
#line 93 "mcrypt.gaa"
	int real_random_flag;
#line 90 "mcrypt.gaa"
	int noecho;
#line 87 "mcrypt.gaa"
	int force;
#line 84 "mcrypt.gaa"
	int timer;
#line 80 "mcrypt.gaa"
	int nodelete;
#line 77 "mcrypt.gaa"
	int unlink_flag;
#line 74 "mcrypt.gaa"
	int double_check;
#line 71 "mcrypt.gaa"
	int flush;
#line 67 "mcrypt.gaa"
	int bzipflag;
#line 64 "mcrypt.gaa"
	int gzipflag;
#line 62 "mcrypt.gaa"
	int bare_flag;
#line 59 "mcrypt.gaa"
	int noiv;
#line 55 "mcrypt.gaa"
	char **keys;
#line 54 "mcrypt.gaa"
	int keylen;
#line 51 "mcrypt.gaa"
	char *hash;
#line 48 "mcrypt.gaa"
	char *modes_directory;
#line 45 "mcrypt.gaa"
	char *mode;
#line 42 "mcrypt.gaa"
	char *algorithms_directory;
#line 39 "mcrypt.gaa"
	char *algorithm;
#line 36 "mcrypt.gaa"
	char *config_file;
#line 35 "mcrypt.gaa"
	int config;
#line 32 "mcrypt.gaa"
	char *keyfile;
#line 29 "mcrypt.gaa"
	char *kmode;
#line 26 "mcrypt.gaa"
	int keysize;
#line 23 "mcrypt.gaa"
	int ed_specified;
#line 22 "mcrypt.gaa"
	int ein;
#line 21 "mcrypt.gaa"
	int din;
#line 17 "mcrypt.gaa"
	int openpgp_z;
#line 13 "mcrypt.gaa"
	int openpgp;

#line 114 "gaa.skel"
};

#ifdef __cplusplus
extern "C"
{
#endif

    int gaa(int argc, char *argv[], gaainfo *gaaval);

    void gaa_help(void);
    
    int gaa_file(const char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
