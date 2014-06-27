/*  mcrypt 2.5 - encrypts text or binary files using symmetric algorithms.
 *  For a brief description of the algorithms read the man page.
 *
 *  Copyright (C) 1998,1999,2000,2001,2002,2007 Nikos Mavroyanopoulos
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


/* $Id: mcrypt.c,v 1.2 2007/11/07 17:10:21 nmav Exp $ */

#ifndef DEFINES_H
#define DEFINES_H
#include <defines.h>
#endif
#include <mcrypt_int.h>
#include <xmalloc.h>
#include <extra.h>
#include <keys.h>
#include <random.h>
#include <gaa.h>
#include <errors.h>
#include <environ.h>
#include <popen.h>
#include <openpgp.h>

#ifdef HAVE_FTIME
# include <sys/timeb.h>
#else
# include <time.h>
#endif

static char rcsid[] =
    "$Id: mcrypt.c,v 1.2 2007/11/07 17:10:21 nmav Exp $";

char tmperr[128];
unsigned int stream_flag = FALSE;
char *keymode = NULL;
char *mode = NULL;
char *algorithm = NULL;
char *hash = NULL;
int keysize;
int nodelete = FALSE;		/* Delete by default */
int noiv = FALSE;
int hash_algorithm = MHASH_CRC32;
int noecho = TRUE;		/* Echo asterisks by default */
int double_check = FALSE;	/* Do not double check for passwords when decrypting */
int quiet = TRUE;		/* silent by default */
int tmpi;
int unlink_flag = FALSE;
int bare_flag = FALSE, real_random_flag = FALSE;
int cleanDelete = FALSE;
#ifdef ZIP
int gzipflag = FALSE;
int bzipflag = FALSE;
#endif
int flush = FALSE;
int timer = FALSE;
int openpgp = FALSE;
int openpgp_z = 0; /* default is no compression */
char *outfile = 0, *tmpc;
char *algorithms_directory = NULL;
char *modes_directory = NULL;
char* program_name = NULL;

void usage(void)
{
	gaa_help();
   fprintf(stdout, _("\n"
		     "Report bugs to mcrypt-dev@lists.hellug.gr.\n\n"));
	exit(0);

}

static char* remove_suffix( char* filename);
void mcrypt_license()
{
   fprintf(stdout,
	   _("\nCopyright (C) 1998-2002 Nikos Mavroyanopoulos\n"
	     "This program is free software; you can redistribute it and/or modify \n"
	     "it under the terms of the GNU General Public License as published by \n"
	     "the Free Software Foundation; either version 2 of the License, or \n"
	     "(at your option) any later version. \n" "\n"
	     "This program is distributed in the hope that it will be useful, \n"
	     "but WITHOUT ANY WARRANTY; without even the implied warranty of \n"
	     "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the \n"
	     "GNU General Public License for more details. \n" "\n"
	     "You should have received a copy of the GNU General Public License \n"
	     "along with this program; if not, write to the Free Software \n"
	     "Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n"));
}

int check_hash_algo(char *chain)
{
   int i;
   char *y;
   char tmp[255];

   for (i = 0; i < 255; i++) {
      y = mhash_get_hash_name(i);
      if (y != NULL) {
	 strcpy(tmp, y);
	 mcrypt_tolow(tmp, strlen(tmp));
	 if (strcmp(tmp, chain) == 0) {
	    return i;
	 }
      }
   }
   return -1;
}


#ifndef LIBMCRYPT_VERSION
# ifdef LIBMCRYPT24
#  define LIBMCRYPT_VERSION "2.4"
# endif
#endif

void mcrypt_version()
{

   fprintf(stderr, _("Mcrypt v.%s (%s-%s-%s)\n"), VERSION, T_CPU,
	   T_VENDOR, T_OS);
   fprintf(stderr, _("Linked against libmcrypt v.%s\n"),
	   mcrypt_check_version(NULL));
   fprintf(stderr,
	   _
	   ("Copyright (C) 1998-2002 Nikos Mavroyanopoulos (nmav@gnutls.org)\n"));

}

/* Checks if the given key size is supported by the algorithm
 */
static void check_keysize( int keysize) {
      int *siz, i, y, x;

      if ( keysize >
	  mcrypt_module_get_algo_key_size(algorithm,
					  algorithms_directory)) {
	 err_quit(_
		  ("The specified key size is too large for this algorithm.\n"));
      }

      siz =
	  mcrypt_module_get_algo_supported_key_sizes(algorithm,
						     algorithms_directory,
						     &i);
      x = 0;
      if (siz == NULL || i == 0)
	 x = 1;			/* we have already checked if it is
				   * less than the maximum supported
				   * by the algorithm
				 */
      else {
	 for (y = 0; y < i; y++) {
	    if (siz[y] == keysize) {
	       x = 1;
	       break;
	    }
	 }
	 free(siz);
      }

      if (x == 0) {
	 err_quit(_
		  ("The specified key size not valid for this algorithm.\n"));
      }
}


/*                              The main    */
int main(int argc, char **argv)
{

   short int ein = 0, din = 0, kin = 0, force = 0, return_val = 0;
   char *einfile = 0, *dinfile = 0, *keyword = 0;
   char **file, **keyfile = NULL, *cfile;
   int x, y, i, file_count = 0, keys = 0, used_algo = FALSE;
   gaainfo info;

#ifdef HAVE_SIGNAL_H
   Signal(SIGINT, shandler);
   Signal(SIGQUIT, shandler);
   Signal(SIGSEGV, shandler);
   Signal(SIGPIPE, shandler);
   Signal(SIGTERM, shandler);
   Signal(SIGHUP, shandler);
   Signal(SIGUSR1, SIG_IGN);
   Signal(SIGUSR2, SIG_IGN);
   Signal(SIGALRM, SIG_IGN);
#endif

#ifdef ENABLE_NLS
   setlocale(LC_ALL, "");
   bindtextdomain(PACKAGE, LOCALEDIR);
   textdomain(PACKAGE);
#endif

   program_name = argv[0];
   
   if ((gaa(argc, argv, &info)) != -1) {
      err_quit(_
	       ("Error in the arguments. Use the --help parameter for more info.\n"));
   }
   if (info.config_file != NULL) {
      cfile = _mcrypt_strdup( info.config_file);
      if (check_file(cfile) != 1) {
	 err_crit(_("Warning: Cannot access config file.\n"));
      }
   } else {
#ifdef HAVE_GETPWUID
      cfile = get_cfile(getuid(), ".mcryptrc");
#else
      cfile = _mcrypt_strdup( ".mcryptrc");
#endif
   }

   /* If config file exists 
    */
   if (check_file(cfile) == 1) {
      if ((gaa_file(cfile, &info)) != -1) {
	 /* gets options from file 'config' */
	 err_quit(_
		  ("Error in the configuration file. Use the --help parameter for more info.\n"));
      }
   }
   _mcrypt_free(cfile);


   if (check_env() == TRUE) {

      if (get_env_key() != NULL) {
	 info.keylen = 1;
	 _mcrypt_free(info.keys);
	 info.keys = get_env_key();
      }
      if (get_env_algo() != NULL) {
	 _mcrypt_free(info.algorithm);
	 info.algorithm = get_env_algo();
      }
      if (get_env_mode() != NULL) {
	 _mcrypt_free(info.mode);
	 info.mode = get_env_mode();
      }
      if (get_env_bit_mode() != 0) {
	 info.kmode = get_env_bit_mode();
      }
   }
/* Check again the command line variables 
 * This will be uncommented when gaa is corrected.
 */

   if (gaa(argc, argv, &info) != -1) {
      err_quit(_
	       ("Error in the arguments. Use the --help parameter for more info.\n"));
   }
/* Examine how we were called */
   if (strstr(program_name, "decrypt") != NULL) {
      Bzero(program_name, strlen(program_name));
      strcpy(program_name, "mdecrypt");
      din = TRUE;
      ein = FALSE;
   } else {
      if (strlen(program_name) > 6) {
	 Bzero(program_name, strlen(program_name));
	 strcpy(program_name, "mcrypt");
      }
      din = FALSE;
      ein = TRUE;		/* It will change by the arguments */
   }



   /* File pointers are as much as the file arguments 
    */

   if ((info.size) * sizeof(char *) > 0) {
      file = _mcrypt_malloc((info.size) * sizeof(char *));
   } else {
      file = NULL;
   }

   if (info.ed_specified != 0) {
      din = info.din;
      ein = info.ein;
   }
   if (info.real_random_flag == TRUE) {
      real_random_flag = TRUE;
   }
   
   force = info.force;
   bare_flag = info.bare_flag;
   unlink_flag = info.unlink_flag;
   quiet = info.quiet;
   noecho = info.noecho;
   noiv = info.noiv;
   double_check = info.double_check;
   flush = info.flush;
   nodelete = info.nodelete;
   timer = info.timer;

   algorithms_directory = info.algorithms_directory;
   modes_directory = info.modes_directory;
#ifdef ZIP
   gzipflag = info.gzipflag;
   bzipflag = info.bzipflag;
#endif

   if (info.kmode != NULL) {
      keymode = info.kmode;
   } else {
      keymode = DEFAULT_KEYMODE;	/* Default */
   }

   if (info.hash != NULL) {
      hash = _mcrypt_strdup( info.hash);
      hash_algorithm = check_hash_algo(hash);

   } else {
      hash = _mcrypt_strdup( HASH_ALGORITHM);
      hash_algorithm = check_hash_algo(hash);
   }

   if (hash_algorithm < 0) {
      fprintf(stderr, _("The '%s' hash algorithm was not found.\n"), hash);
      fprintf(stderr,
	      _
	      ("Use the --hashlist parameter to view all supported hashes.\n"));
      exit(1);
   }

   if (info.keyfile != NULL) {
      kin = 2;
      keyfile = read_key_file(info.keyfile, &keys);
      if (keyfile == NULL)
	 kin = 0;
      if (keys == 0)
	 kin = 0;
   } else {
      if (info.keys != NULL) {
	 kin = 2;
	 keyfile = _mcrypt_malloc(info.keylen * sizeof(char *));
	 keys = info.keylen;

	 for (i = 0; i < info.keylen; i++) {
	    keyfile[i] = _secure_mcrypt_malloc(strlen(info.keys[i]) + 10);
	    strcpy(keyfile[i], info.keys[i]);
	 }
      }
   }

   if (info.mode != NULL) {
      mode = strdup(info.mode);
      mcrypt_tolow( mode, strlen(mode));
   } else {
      mode = DEFAULT_MODE;
   }

   openpgp = info.openpgp;
   if (openpgp!=0) {
   	mode = DEFAULT_PGP_MODE;
   	if (strncasecmp( "s2k", keymode, 3)!=0) {
   		keymode = DEFAULT_PGP_KEYMODE;
   	}
   }
   openpgp_z = info.openpgp_z;
   if ( openpgp_z < 0 || openpgp_z > 9 ) {
   	err_quit(_("Illegal compression level\n"));
   }

   if (info.algorithm != NULL) {
      used_algo = TRUE;
      algorithm = _mcrypt_strdup( info.algorithm);

      mcrypt_tolow( algorithm, strlen(algorithm));

      i = mcrypt_module_is_block_algorithm(algorithm,
					   algorithms_directory);

      if (i < 0) {
	 fprintf(stderr, _("Error in algorithm '%s'.\n"), algorithm);
	 exit(1);
      }

      if (i == 0) {
	 y = mcrypt_module_is_block_algorithm_mode(mode, modes_directory);
	 if (y >= 0) {
	    mode = "stream";
	 } else {
	    fprintf(stderr, _("Error in mode '%s'.\n"), mode);
	    exit(1);
	 }
      }

   } else {
      algorithm = DEFAULT_ALGORITHM;
   }

   if ( mode != NULL) {
      y = mcrypt_module_is_block_algorithm_mode(mode, modes_directory);
      if (y < 0) {
	 fprintf(stderr, _("Error in mode '%s'.\n"), mode);
	 exit(1);
      }
   }

   keysize = info.keysize;
   if ( keysize != 0) {
	check_keysize (keysize);

   } else
   	keysize = mcrypt_module_get_algo_key_size(algorithm, algorithms_directory);

   if (info.keylen != 0 && check_env() == FALSE) {
      err_warn(_
	       ("Warning: It is insecure to specify keywords in the command line\n"));
   }
#ifdef HAVE_UMASK
   umask(066);
#endif

/* For RAND32... Called only here */
#ifndef HAVE_DEV_RANDOM
      err_warn(_
	       ("Warning: This system does not have a random device. "
	       "Will use the included entropy gatherer.\n"));
#endif
   mcrypt_init_random();

/* Normal startup 
 */


/* ok now how many files were specified? */
   i = 0;

   /* '-' is used to refer to stdin */
   if (info.size == 1 && strcmp(info.input[0], "-") == 0)
      info.size -= 1;

   file_count += (info.size);

   if (file_count == 0) {
      stream_flag = TRUE;
   }
   while (i < info.size) {
      file[i] = info.input[i];
      i++;
   }


   if (stream_flag == TRUE)
      file_count++;

/* Do as many times as many files we got */
   for (i = 0; i < file_count; i++) {

      if (i != 0) {
	 if (outfile != NULL)
	    _mcrypt_free(outfile);
      }

      /* If keyword file specified choose the i-th keyword */

      if (kin == 2 && i <= (keys - 1)) {
	 keyword = keyfile[i];
	 if (i != 0) {
	    _secure_mcrypt_free(keyfile[i - 1], strlen(keyfile[i - 1]));	/* Free previous keyword */
	 }
      }
#ifdef HAVE_STAT
      if (stream_flag == FALSE) {
	 if (is_normal_file(file[i]) == FALSE) {
	    sprintf(tmperr,
		    _
		    ("%s: %s is not a regular file. Skipping...\n"),
		    program_name, file[i]);
	    err_crit(tmperr);
	    outfile = NULL;
	    continue;		/* next */
	 }
      }
#endif


      /* Check how we were called */
      if (din == TRUE) {	/* decryption */
      
	 if (stream_flag != TRUE)
	    dinfile = file[i];
	 if ((isatty(fileno((FILE *) (stdin))) == 1)
	     && (stream_flag == TRUE) && (force == 0)) {	/* not a tty */
	    sprintf(tmperr,
		    _
		    ("%s: Encrypted data will not be read from a terminal.\n"),
		    program_name);
	    err_crit(tmperr);
	    err_quit(_
		     ("Redirect the input instead.\nUse the --help parameter for more help.\n"));
	 }

         /* this will enable the pgp flag if it is a pgp file.
          * or disable it otherwise.
          */
         test_file_headers( dinfile);

      } else {			/* encryption */
	 if (stream_flag != TRUE)
	    einfile = file[i];
	 if ((isatty(fileno((FILE *) (stdout))) == 1)
	     && (stream_flag == TRUE) && (force == 0)) {	/* not a tty */
	    sprintf(tmperr,
		    _
		    ("%s: Encrypted data will not be written to a terminal.\n"),
		    program_name);
	    err_crit(tmperr);
	    err_quit(_
		     ("Redirect the output instead.\nUse the --help parameter for more help.\n"));
	 }
      }


      /* If no streams make the extensions */
      if (stream_flag != TRUE) {

	 if (din == TRUE) {
	 	outfile = remove_suffix( dinfile);
	 	if (outfile==NULL)
	 		continue;

	 } else {		/* encryption- append .nc */
	    outfile = _mcrypt_calloc(strlen(einfile) + 5 + 4, 1);
	    strcpy(outfile, einfile);
	    /* if file has already the .nc ignore it */
	    if (strstr(outfile, ".nc") != NULL) {
	       sprintf(tmperr,
		       _
		       ("%s: file %s has the .nc suffix... skipping...\n"),
		       program_name, outfile);
	       err_crit(tmperr);
	       continue;
	    }
#ifdef ZIP
	    if (stream_flag == FALSE) {
	       if (gzipflag == TRUE)
		  strcat(outfile, ".gz");
	       if (bzipflag == TRUE)
		  strcat(outfile, ".bz2");
	    }
#endif
	    strcat(outfile, ".nc");
#ifdef HAVE_STAT
	    /* But if it exists exit */
	    if (check_file(outfile) != 0) {
	       cleanDelete = FALSE;
	       if (ask_overwrite(program_name, outfile)
		   == FALSE) {
		  continue;
	       } else {
		  cleanDelete = TRUE;
	       }

	    } else {
	       cleanDelete = TRUE;
	    }
#endif

	 }
      } else {			/* if streams */
	 outfile = NULL;
      }



/* Decrypt */
      if (din == TRUE) {
	 if (openpgp!=0) x = pgp_decrypt_wrap( dinfile, outfile, keyword);
	 else x = decrypt_general(algorithm, dinfile, outfile, keyword);

	 if (x == 0) {
	    if (stream_flag == FALSE) {
	       sprintf(tmperr, _("File %s was decrypted.\n"), dinfile);
	       err_warn(tmperr);
	    } else {
	       sprintf(tmperr, _("Stdin was decrypted.\n"));
	       err_warn(tmperr);
	    }
#ifdef HAVE_STAT
# ifdef HAVE_UTIME_H
	    if (stream_flag == FALSE)
	       copyDate(dinfile, outfile);
# endif
#endif

	    if (unlink_flag == TRUE && stream_flag == FALSE)
	       x = unlink(dinfile);
	    if (x != 0)
	       perror("unlink");

	 } else {
	    if (stream_flag == FALSE) {
	       sprintf(tmperr,
		       _
		       ("File %s was NOT decrypted successfully.\n"),
		       dinfile);
	       err_crit(tmperr);
	       if (x != -1) {
		  if (nodelete == FALSE)
		     remove(outfile);
	       } else {
		  x = 1;
	       }
	    } else {
	       err_crit(_("Stdin was NOT decrypted successfully.\n"));
	    }
	 }

	 return_val += x;
      }

/* Encrypt */
      if (ein == TRUE) {
	 if (openpgp!=0) x = pgp_encrypt_wrap( einfile, outfile, keyword);
	 else x = encrypt_general(algorithm, einfile, outfile, keyword);

	 if (x == 0) {
	    if (stream_flag == FALSE) {
	       sprintf(tmperr, _("File %s was encrypted.\n"), einfile);
	       err_warn(tmperr);
	    } else {
	       sprintf(tmperr, _("Stdin was encrypted.\n"));
	       err_warn(tmperr);
	    }
#ifdef HAVE_STAT
#ifdef HAVE_UTIME_H
	    if (stream_flag == FALSE)
	       copyDate(einfile, outfile);
#endif
#endif
	    if (unlink_flag == TRUE && stream_flag == FALSE)
	       x = unlink(einfile);
	    if (x != 0)
	       perror("unlink");

	 } else {
	    if (stream_flag == FALSE) {
	       sprintf(tmperr,
		       _
		       ("File %s was NOT encrypted successfully.\n"),
		       einfile);
	       err_crit(tmperr);
	       if (x != -1) {
		  if (nodelete == FALSE)
		     remove(outfile);
	       } else {
		  x = 1;
	       }
	    } else {
	       err_crit(_("Stdin was NOT encrypted successfully.\n"));
	    }

	 }


	 return_val += x;
      }
   }				/* the main loop */

/* Clear the last keyword used */
   if (keyword != NULL) {
      Bzero(keyword, strlen(keyword));
      _mcrypt_free(keyword);
   }

/* Clear ALL arguments in the command line */
   for (i = 0; i < argc; i++) {
      Bzero(argv[i], strlen(argv[i]));
   }

   mcrypt_deinit_random();

   if (return_val != 0) {
      return 1;
   } else {
      return 0;
   }

}


int make_mult(int num, int d)
{
   int i = 0;

   while (i < num) {
      i += d;
   }
   return i;
}

static char* remove_suffix( char* filename) {
int y;
char* outfile;
	    
    y = strlen(filename);
    /* If the file has the .nc suffix, then remove it */

    if ((filename[y - 1] == 'c'
	 && filename[y - 2] == 'n' && filename[y - 3] == '.')) {

       outfile = _mcrypt_calloc(y - 2, 1);
       strncpy(outfile, filename, y - 3);

    } else /* gpg files */ if ((filename[y - 1] == 'g'
	 && filename[y - 2] == 'p' && filename[y - 3] == 'g'
	 && filename[y - 4] == '.')) {

	       	outfile = _mcrypt_calloc(y - 3, 1);
		strncpy(outfile, filename, y - 4);
    } else { /* append .dc */
       err_warn(_("Unknown suffix. Will append '.dc'.\n"));

       cleanDelete = TRUE;
       outfile = _mcrypt_calloc(y + 5, 1);
       strncpy(outfile, filename, y);
       strcat(outfile, ".dc");

    }

#ifdef HAVE_STAT
       /* But if it exists exit */
       if (check_file(outfile) != 0) {
	  cleanDelete = FALSE;
	  if (ask_overwrite( program_name, outfile) == FALSE) {
	     return NULL;
	  } else {
	     cleanDelete = TRUE;
	  }
       } else {
	  cleanDelete = TRUE;
       }
#endif

	return outfile;
}
