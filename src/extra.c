/*
 *    Copyright (C) 1998,1999,2000,2001,2002,2003 Nikos Mavroyanopoulos
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

/* Some functions that didn't fit elsewhere */

/* $Id: extra.c,v 1.2 2007/11/07 17:10:20 nmav Exp $ */

#ifndef DEFINES_H
#define DEFINES_H
#include <defines.h>
#endif

#include "extra.h"
#include <xmalloc.h>
#include <errors.h>
#ifndef NO_GETPASS
# include <getpass.h>
#else
# define _mcrypt_getpass getpass
#endif
#include <keys.h>
#include <bits.h>
#include "mcrypt_int.h"

#ifdef HAVE_FTIME
# include <sys/timeb.h>
#else
# include <time.h>
#endif

static char rcsid[] =
    "$Id: extra.c,v 1.2 2007/11/07 17:10:20 nmav Exp $";

#ifndef NO_GETPASS
	#define FREE_STR(x) \
		_secure_mcrypt_free(x, strlen(x))
#else
	#define FREE_STR(x) \
		Bzero(x, strlen(x))
#endif

extern int openpgp;
extern int bare_flag;
extern int quiet;
extern int double_check;
extern char *outfile;
extern char* algorithm;
extern int keysize;
extern char* mode;
extern char* keymode;
extern int stream_flag;
extern int bare_flag;
extern int cleanDelete;
extern int noiv;
extern int hash_algorithm;

char *my_getpass(char *prt)
{
	char *atmp;
	static char ztmp[MAX_KEY_LEN];
	char *btmp;
	char string_tmp[200];

	if (ztmp==NULL) return NULL;
	
	atmp = _mcrypt_getpass(prt);
	if (atmp==NULL) {
		return NULL;
	}
	
	Bzero(string_tmp, sizeof(string_tmp));
	Bzero(ztmp, MAX_KEY_LEN);
	strlcpy(ztmp, atmp, MAX_KEY_LEN);

	strcpy(string_tmp, prt);

	btmp = _mcrypt_getpass(string_tmp);
	if (btmp==NULL) {
		return NULL;
	}

	if (strcmp(ztmp, btmp) != 0) {
		fprintf(stderr,
			_
			("Keywords do not match or they are too long.\n"));

		return NULL;
	}
	fprintf(stderr, "\n");
	
	return ztmp;
}

char *get_password( int mode, unsigned int *len)
{

	char *tmp = NULL;
	char msg[200];

	sprintf(msg, _("Enter passphrase: "));

	if (mode == ENCRYPT) {
		fprintf(stderr,
			_
			("Enter the passphrase (maximum of %d characters)\n"),
			MAX_KEY_LEN - 1);
		fprintf(stderr,
			_
			("Please use a combination of upper and lower case letters and numbers.\n"));
		tmp = my_getpass(msg);

	} else {
		if (double_check == FALSE) {
			tmp = _mcrypt_getpass(msg);
		} else {
			tmp = my_getpass(msg);
		}
	}
	
	if (tmp == NULL)
		return NULL;

	*len = strlen(tmp);
	return tmp;

}


int check_file(char *filename)
{
FILE* fd;

	fd = fopen( filename, "r");
	if ( fd == NULL) return 0; /* does not exist  */
	
	fclose( fd);
	
	return 1; /* ok, it exists */
}


void read_until_null(char *pointer, FILE * fstream)
{
	int i;

	for (i = 0; i < 100; i++) {
		fread(&pointer[i], 1, 1, fstream);
		if (pointer[i] == 0)
			break;
	}

}

int check_file_head(FILE * fstream, char *algorithm, char *mode,
		    char *keymode, int *keysize, void *salt,
		    int *salt_size)
{
	char buf[3];
	char tmp_buf[101];
	short int keylen;
	unsigned char flags;
	unsigned char sflag;

	if (stream_flag == TRUE) {
		fstream = (FILE *) stdin;
	}

	fread(buf, 1, 3, fstream);
	fread(&flags, 1, 1, fstream);

	if (buf[0] == '\0' && buf[1] == 'm' && buf[2] == '\3') {
		/* if headers are ok */

		if (m_getbit(0, flags) != 0) {
			err_crit(_
				 ("Unsupported version of encrypted file\n"));
			return -1;
		}
		if (m_getbit(1, flags) != 0) {
			err_crit(_
				 ("Unsupported version of encrypted file\n"));
			return -1;
		}
		if (m_getbit(2, flags) != 0) {
			err_crit(_
				 ("Unsupported version of encrypted file\n"));
			return -1;
		}
		if (m_getbit(3, flags) != 0) {
			err_crit(_
				 ("Unsupported version of encrypted file\n"));
			return -1;
		}
		if (m_getbit(4, flags) != 0) {
			err_crit(_
				 ("Unsupported version of encrypted file\n"));
			return -1;
		}
		if (m_getbit(5, flags) != 0) {
			err_crit(_
				 ("Unsupported version of encrypted file\n"));
			return -1;
		}

		if (m_getbit(7, flags) != 0) {
			err_warn(_
				 ("No Initialization vector was used.\n"));
			noiv = TRUE;	/* No iv is being used */
		}

		read_until_null(tmp_buf, fstream);
		strcpy(algorithm, tmp_buf);

		fread(&keylen, sizeof(short int), 1, fstream);
#ifdef WORDS_BIGENDIAN
		*keysize = byteswap16(keylen);
#else
		*keysize = keylen;
#endif

		read_until_null(tmp_buf, fstream);
		strcpy(mode, tmp_buf);

		read_until_null(tmp_buf, fstream);
		strcpy(keymode, tmp_buf);
		fread(&sflag, 1, 1, fstream);
		if (m_getbit(6, flags) == 1) { /* if the salt bit is set */
			if (m_getbit(0, sflag) != 0) { /* if the first bit is set */
				*salt_size = m_setbit(0, sflag, 0);
				if (*salt_size > 0) {
					fread(tmp_buf, 1, *salt_size,
					      fstream);
					memmove(salt, tmp_buf, *salt_size);
				}
			}
		}

		read_until_null(tmp_buf, fstream);	/* hash name ignored
							 * crc32 assumed 
							 */
		hash_algorithm = check_hash_algo(tmp_buf);

		return 0;
	} else {		/* No headers present */
		if (buf[0] == '\0' && buf[1] == 'm' && buf[2] == '\2') {
			err_crit(_
				 ("This is a file encrypted with the 2.2 version of mcrypt. Unfortunately you'll need that version to decrypt it.\n"));
			return 1;
		}
		if (buf[0] == '\0' && buf[1] == 'm' && buf[2] == '\1') {
			err_crit(_
				 ("This is a file encrypted with the 2.1 version of mcrypt. Unfortunately you'll need that version to decrypt it.\n"));
			return 1;
		}
		err_crit(_
			 ("Unable to get algorithm information. Use the --bare flag and specify the algorithm manualy.\n"));

		return 1;
	}

}


void *read_iv(FILE * fstream, int ivsize)
{
	char *IV;

	if (stream_flag == TRUE) {
		fstream = (FILE *) stdin;
	}

	IV = _mcrypt_malloc(ivsize);
	fread(IV, 1, ivsize, fstream);

	return IV;

}

void mcrypt_tolow(char *str, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		str[i] = tolower(str[i]);
	}
}


int write_file_head(FILE * filedes, char *algorithm, char *mode,
		    char *keymode, int *keysize, void *salt, int salt_size)
{
	char *buf;
	short int keylen = *keysize;
	unsigned char null = 0;
	unsigned char sflag = 0;
	char tmp[255];

	buf = _mcrypt_malloc(4);

	buf[0] = '\0';
	buf[1] = 'm';
	buf[2] = '\3';
	buf[3] = '\0';		/* flags not yet fully supported */

	if (salt != NULL)
		buf[3] = m_setbit(6, buf[3], 1);
	if (noiv == TRUE)
		buf[3] = m_setbit(7, buf[3], 1);

	if (fwrite(buf, 1, 4, filedes) != 4) {
		return 1;
	}
	_mcrypt_free(buf);

	if (fwrite(algorithm, 1, strlen(algorithm), filedes) !=
	    strlen(algorithm)) {
		return 1;
	}
	if (fwrite(&null, 1, 1, filedes)!=1) return 1;

#ifdef WORDS_BIGENDIAN
	keylen = byteswap16(keylen);
#endif
	if (fwrite(&keylen, 1, sizeof(short int), filedes) !=
	    sizeof(short int)) {
		return 1;
	}

	if (fwrite(mode, 1, strlen(mode), filedes) != strlen(mode)) {
		return 1;
	}
	if (fwrite(&null, 1, 1, filedes)!=1) return 1;

	if (fwrite(keymode, 1, strlen(keymode), filedes) !=
	    strlen(keymode)) {
		return 1;
	}
	if (fwrite(&null, 1, 1, filedes)!=1) return 1;

	if (salt != NULL) {
		sflag = salt_size;
		sflag = m_setbit(0, sflag, 1);
		fwrite(&sflag, 1, 1, filedes);
		if (fwrite(salt, 1, salt_size, filedes) != salt_size) {
			return 1;
		}
	}



	buf = mhash_get_hash_name(hash_algorithm);
	if (buf!=NULL) {
		strcpy(tmp, buf);
		mcrypt_tolow(tmp, strlen(tmp));
	} else
		return 1;
		
	if (fwrite(tmp, 1, strlen(tmp), filedes) != strlen(tmp)) {
		return 1;
	}
	if (fwrite(&null, 1, 1, filedes)!=1) return 1;


	return 0;

}


int write_iv(FILE * filedes, void *IV, int ivsize)
{
	unsigned char *buf = NULL;

	if (ivsize > 0) {
		buf = _mcrypt_malloc(ivsize);
		if (IV != NULL) {
			Bzero(buf, ivsize);
			memmove(buf, IV, ivsize);
		} else {
			Bzero(buf, ivsize);
		}
		if (fwrite(buf, 1, ivsize, filedes) != ivsize) {
			return 1;
		}
	}

	_mcrypt_free(buf);
	return 0;

}

#ifdef HAVE_STAT
#ifdef HAVE_UTIME
void copyDate(char *srcName, char *dstName)
{
	int retVal;
	struct stat statBuf;
	struct utimbuf uTimBuf;

	retVal = stat(srcName, &statBuf);
	if (retVal == -1)
		perror("stat");

	uTimBuf.actime = statBuf.st_atime;
	uTimBuf.modtime = statBuf.st_mtime;

	retVal = utime(dstName, &uTimBuf);
	if (retVal == -1)
		perror("utime");
}
#endif


int is_normal_file(char *filename)
{
	struct stat statBuf;

#ifdef HAVE_LSTAT		/* Do not treat symlinks as regular files */
	if (lstat(filename, &statBuf) != 0)
		return FALSE;
#else
	if (stat(filename, &statBuf) != 0)
		return FALSE;
#endif

	if (S_ISREG(statBuf.st_mode) != 0) {
		return TRUE;
	} else {
		return FALSE;
	}

}

#endif

void shandler(int signal)
{

	fprintf(stderr, _("Signal %d caught. Exiting.\n"), signal);
#ifdef SIGSEGV
	if (signal != SIGSEGV)
#endif
		cleanUp();
	exit(-1);

}

void snhandler(int signal)
{

	fprintf(stderr, _("\nSignal %d caught. Exiting.\n"), signal);
	cleanUp();
	exit(-1);

}

void cleanUp()
{

	fflush(NULL);
	if (stream_flag == FALSE && cleanDelete == TRUE)
		remove(outfile);	/* Delete the file we were writing to */

}


char **read_key_file(char *file, int *num)
{

	FILE *FROMF;
	char keyword[MAX_KEY_LEN], **keys = NULL;
	int x = 0;

	FROMF = fopen(file, "r");
	if (FROMF == NULL) {
		fprintf(stderr,
			_("Keyfile could not be opened. Ignoring it.\n"));
		return NULL;
	}

	while (fgets(keyword, MAX_KEY_LEN, FROMF) != NULL) {
		x++;
		keys = _mcrypt_realloc(keys, x * sizeof(char *));
		keys[x - 1] = _mcrypt_malloc(strlen(keyword) + 1);
/* Remove newline */
		if (keyword[strlen(keyword) - 1] == '\n')
			keyword[strlen(keyword) - 1] = '\0';
		strcpy(keys[x - 1], keyword);

	}

	*num = x;

	return keys;

}

#ifdef HAVE_GETPWUID
char *get_cfile(int uid, char *cfile)
{

	char *home;
	struct passwd *pwd;

	pwd = getpwuid(uid);

	if (pwd != NULL) {
		home = _mcrypt_malloc(strlen(pwd->pw_dir) + strlen(cfile) + 2);
		strcpy(home, pwd->pw_dir);
		strcat(home, "/");
	} else {
		home = _mcrypt_calloc(1, strlen(cfile) + 2);
	}
	strcat(home, cfile);

	return home;

}
#endif


int ask_overwrite(char *name, char *file)
{
	char x[2];
	int tty_opened = 0;
	FILE *fp;

#ifdef HAVE_SIGNAL_H
	Signal(SIGINT, snhandler);
	Signal(SIGQUIT, snhandler);
	Signal(SIGSEGV, snhandler);
	Signal(SIGPIPE, snhandler);
	Signal(SIGTERM, snhandler);
	Signal(SIGHUP, snhandler);
#endif


	fprintf(stderr,
		_
		("%s: %s already exists; do you wish to overwrite (y or n)?"),
		name, file);

	if ((fp = fopen("/dev/tty", "r")) == 0) {
		fp = stdin;
		setbuf(fp, NULL);
	} else {
		tty_opened = 1;
	}

	x[0] = fgetc(fp);
	x[1] = '\0';

	if (tty_opened != 0)
		fclose(fp);

#ifdef HAVE_SIGNAL_H
	Signal(SIGINT, shandler);
	Signal(SIGQUIT, shandler);
	Signal(SIGSEGV, shandler);
	Signal(SIGPIPE, shandler);
	Signal(SIGTERM, shandler);
	Signal(SIGHUP, shandler);
#endif

	if (strcoll(x, "y") == 0 || strcoll(x, "Y") == 0) {
		return TRUE;
	} else {
		return FALSE;
	}

}


void Bzero(void *s, size_t n)
{
#ifdef HAVE_MEMSET
	memset((void *) s, '\0', (size_t) n);
#else
# ifdef HAVE_BZERO
	bzero((void *) s, (size_t) n);
# else
	char *stmp = s;

	for (int i = 0; i < n; i++)
		stmp[i] = '\0';

# endif
#endif
}


/* This function will check the first by of the file and will tell
 * if this is an openpgp file or not.
 */

void test_file_headers( char* file) {
unsigned char x;

	if (file==NULL) {
		x = getc( stdin);
		if (ungetc( x, stdin)==EOF) {
			err_quit(_("Could not push character back to stream\n"));
		}
	} else {
		FILE* fd;
		
		fd = fopen( file, "rb");
		if (fd == NULL) {
		   perror("fopen");
		   err_quit(_("Could not open file\n"));
		}
		x = getc( fd);
		fclose(fd);
	}

	if (x==0) { /* mcrypt file format */
		openpgp = 0;
		return;
	}
	
	if ( !(!x & 0x80) && bare_flag == FALSE) {
		if (openpgp==0) {
			err_warn(_("An OpenPGP encrypted file has been detected.\n"));
		}
		openpgp = 1;
	}
	return;
}


void print_enc_info(const char* infile, const char* outfile) {
char tmperr[256];
char* fmt;

   if (quiet == FALSE) {
      fprintf(stderr,
	      _
	      ("Algorithm: %s\nKeysize: %d\nMode: %s\nKeyword mode: %s\n"),
	      algorithm, keysize, mode, keymode);
      if (openpgp != FALSE)
      	fmt = "openpgp";
      else if (bare_flag==FALSE)
        fmt = "mcrypt";
      else fmt = "bare";
      
      fprintf(stderr, _("File format: %s\n"), fmt);

   }
   
   if ( stream_flag == FALSE) {
      sprintf(tmperr, _("Input File: %s\n"), infile);
      err_info(tmperr);

      sprintf(tmperr, _("Output File: %s\n"), outfile);
      err_info(tmperr);
   }

   err_info("\n");

}

extern int timer; /* mcrypt.c */

#ifdef HAVE_FTIME
 static struct timeb start_time;
 static struct timeb end_time;
#else
 static time_t start_time;
 static time_t end_time;
#endif

void _mcrypt_start_timer(void) {

#ifdef HAVE_FTIME
 ftime(&start_time);
#else
 start_time = time(0);
#endif
}

void _mcrypt_end_timer(void) {
#ifdef HAVE_FTIME
 ftime(&end_time);
#else
 end_time = time(0);
#endif


}

/* Accepts time elapsed in milliseconds and file size in bytes.
 */
static void show_stats2(time_t ms_time, size_t file_size)
{
   time_t time = ms_time / 1000;
   time_t millitm = ms_time % 1000;
   int show = 0;

   fprintf(stderr, _("Time needed: "));

   if (time / 3600 > 0) {
      fprintf(stderr, _("%lu hours"), time / 3600);
      show = 1;
   }

   if ((time / 60) - ((time / 3600) * 60) > 0) {
      if (show > 0)
	 fprintf(stderr, ", ");
      fprintf(stderr, _("%lu minutes"), (time / 60) - (time / 3600));
      show = 1;
   }

   if (time - ((time / 60) + ((time / 3600) * 60) * 60) > 0) {
      if (show > 0)
	 fprintf(stderr, ", ");
      fprintf(stderr, _("%lu seconds"), time - ((time / 60) + (time / 3600)));
      show = 1;
   }

   if (millitm > 0) {
      if (show > 0)
	 fprintf(stderr, ", ");
      fprintf(stderr, _("%lu milliseconds"), millitm);
      show = 1;
   }

   if (show == 0)
      fprintf(stderr, _("Wow, no time counted!\n"));
   else {
      fprintf(stderr, ".\n");

      if (file_size > 1000000) {
	 fprintf(stderr,
		 _
		 ("Processed %.3f MB, at a %.3f MB/sec rate (1 MB == 1000000 Bytes).\n\n"),
		 (float) ((double) file_size / (double) 1000000),
		 (float) ((((double) file_size / (double) 1000000) /
			   (double) ms_time) * (double) 1000));
      } else {			/* KB */
	 fprintf(stderr,
		 _
		 ("Processed %.3f KB, at a %.3f KB/sec rate (1 KB == 1000 Bytes).\n\n"),
		 (float) ((double) file_size / (double) 1000),
		 (float) ((((double) file_size / (double) 1000) /
			   (double) ms_time) * (double) 1000));
      }
   }
}

void _mcrypt_time_show_stats( size_t file_sum) {
   if (timer != FALSE && file_sum > 0) {
#ifdef HAVE_FTIME
      end_time.time *= 1000;
      end_time.time += end_time.millitm;

      start_time.time *= 1000;
      start_time.time += start_time.millitm;

      end_time.time -= start_time.time;

      start_time.time = end_time.time;

      end_time.millitm = end_time.time % 1000;

      show_stats2(end_time.time, file_sum);

#else
      end_time -= start_time;

      show_stats2(end_time, file_sum);

#endif

   }
}
