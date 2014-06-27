/*
 *    Copyright (C) 1998,1999,2000,2001,2002 Nikos Mavroyanopoulos
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

extern char tmperr[];
extern unsigned int stream_flag;
extern char *keymode;
extern char *mode;
extern char *algorithm;
extern char *hash;
extern int keysize;
extern int nodelete;
extern int noiv;
extern int hash_algorithm;
extern int noecho;
extern int double_check;
extern int quiet;
extern int tmpi;
extern int unlink_flag;
extern int bare_flag, real_random_flag;
extern int cleanDelete;
#ifdef ZIP
extern int gzipflag;
extern int bzipflag;
#endif
extern int flush;
extern char *outfile, *tmpc;
extern char *algorithms_directory;
extern char *modes_directory;

int make_mult(int num, int d);


/* General Encryption 
 * nothing to do with general Lee.
 * This is the original mcrypt encryption and decryption
 * code. This is a mess.
 */

/* Reading from now on offers nothing to the reader except
 * of a brain damage.
 */

static int _mcrypt_iv_is_needed( MCRYPT td, char* mode, int noiv) {
   if (noiv!=0) return 0; /* no IV */

   /* stream mode is treated differently because
    * some stream ciphers use IVs even if the mode itself doesn't.
    */
   if ( strcmp(mode, "stream")==0 && mcrypt_enc_get_iv_size(td) != 0) {
   	return 1;
   }
   
   if ( mcrypt_enc_mode_has_iv(td) != 0 && mcrypt_enc_get_iv_size(td) != 0) {
	return 1;
   }

   return 0;
}

int
encrypt_general(char *algorithm, char *fromfile, char *tofile, char *key)
{
   int full_blocks = 0, rest_blocks = 0;
   char *fcrc32 = NULL;
   word32 *keyword;
   int tc, enc_bytes;
   MHASH tm = 0;
   int how = 0, clen;
   unsigned int len = 0;
   FILE *FROMF;
   int keylen, salt_size;
   int blocksize;
   MCRYPT td;
   int pad_size;
   char *command = NULL;
   keygenid ki;
   word32 *IV = NULL;
   word32 *salt = NULL;
   int hash_size = mhash_get_block_size(hash_algorithm);
   size_t file_sum = 0;

   byte *ciphertext, *ciphertext_pad = NULL;
   FILE *TOF = NULL;

   td = mcrypt_module_open(algorithm, algorithms_directory, mode,
			   modes_directory);

   if (td == MCRYPT_FAILED) {
      err_crit(_("Mcrypt failed to open module.\n"));
      return 1;
   }

   if (keysize == 0)
      keysize = mcrypt_enc_get_key_size(td);

   keylen = keysize;
   blocksize = mcrypt_enc_get_block_size(td);

   ciphertext = _mcrypt_malloc(blocksize * BUFFER_SIZE);

   /* Generate the SALT
    */
   if (bare_flag == FALSE) {
      salt = _mcrypt_malloc(SALT_SIZE);	/* 20 bytes salt */

      /* Fill the salt with random data */
      mcrypt_randomize( salt, SALT_SIZE, real_random_flag);
   }


   /* Generate the IV 
    */
   IV = _secure_mcrypt_malloc(mcrypt_enc_get_iv_size(td));
   if (noiv==FALSE)
	   mcrypt_randomize( IV, mcrypt_enc_get_iv_size(td), real_random_flag);
   else
   	   memset( IV, 0, mcrypt_enc_get_iv_size(td));


#ifdef DEBUG
   fprintf(stderr, "IV: ");
   for (i = 0; i < blocksize; i++) {
      fprintf(stderr, "%.2x.", ((unsigned char *) IV)[i]);
   }
   fprintf(stderr, "\n");
#endif

/* open files */
   if (stream_flag == TRUE 
#ifdef ZIP
   && (gzipflag == FALSE && bzipflag == FALSE)
#endif
   ) {
      FROMF = stdin;
      TOF = stdout;
   } else {
#ifdef ZIP
      if (gzipflag == FALSE && bzipflag == FALSE) {
#endif
	 FROMF = fopen(fromfile, "rb");
	 if (FROMF == NULL) {
	    perror("fopen");
	    return 1;
	 }

	 TOF = fopen(tofile, "wb");
	 if (TOF == NULL) {
	    perror("fopen");
	    return -1;
	 }
#ifdef ZIP
      } else {
         err_info( "Output file will be compressed.\n");

	 /* command if using gzip */
	 clen = 5;
	 if (fromfile != NULL)
	    clen += strlen(fromfile);

	 if (gzipflag == TRUE) {
	    clen += strlen(GZIP);
	    command = _mcrypt_malloc(clen);
	    strcpy(command, GZIP);
	 }
	 if (bzipflag == TRUE) {
	    clen += strlen(BZIP2);
	    command = _mcrypt_malloc(clen);
	    strcpy(command, BZIP2);
	 }
	 strcat(command, " -c ");
	 if (fromfile != NULL)
	    strcat(command, fromfile);

	 if (stream_flag == FALSE) {
	    FROMF = popen(command, "r");
	    TOF = fopen(tofile, "wb");
	 } else {		/* stream_flag==TRUE */
	    if (ppopen(command, NULL, &FROMF) <= 0) {
	       err_crit("ppopen error\n");
	       return -1;
	    }
	    TOF = stdout;
	 }

	 if (FROMF == NULL || TOF == NULL) {
	    perror("ppopen");
	    return 1;
	 }

      }
#endif
   }



   ki = _which_algo(keymode);
   if (ki == -1) {
      fprintf(stderr, _("Error in keymode '%s'.\n"), keymode);
      return 1;
   }
   if (mhash_keygen_uses_salt(ki) == 1) {
      salt_size = mhash_get_keygen_salt_size(ki);
      if (salt_size == 0)
	 salt_size = SALT_SIZE;
   } else {
      salt_size = 0;
   }

   if (bare_flag == FALSE) {
      if (write_file_head(TOF, algorithm, mode, keymode, &keysize,
			  salt, salt_size) != 0) {
	 err_crit("Error writing file\n");
	 return -1;
      }
   }

   if (_mcrypt_iv_is_needed(td, mode, noiv) != 0) {
      if (write_iv(TOF, IV, mcrypt_enc_get_iv_size(td)) != 0) {
	 err_crit("Error writing file\n");
	 return -1;
      }
   }

   if (flush == TRUE)
      fflush(TOF);


/* Get keyword */
   if (key == NULL) {
      keyword =
	  fixkey(NULL, &len, keymode, keysize, quiet,
		 stream_flag, salt, salt_size, ENCRYPT);
   } else {
      len = strlen(key);
      keyword =
	  fixkey(key, &len, keymode, keysize, quiet,
		 stream_flag, salt, salt_size, ENCRYPT);
   }
   if (keyword == NULL) {
      err_crit("There was an error in key generation\n");
      return 1;
   }

   _mcrypt_start_timer();
   tc = mcrypt_generic_init(td, keyword, len, IV);
   if (tc < 0) {
      mcrypt_perror(tc);
      return 1;
   }

   if (bare_flag == FALSE) {
      tm = mhash_init(hash_algorithm);

      if (tm==NULL)
         err_quit(_("mhash initialization failed.\n"));

   }

/* Encryption Starts here */
   /* read the first n bytes of the file and store to ciphertext */
   for (;;) {
      how = fread(ciphertext, 1, blocksize * BUFFER_SIZE, FROMF);
      file_sum += how;

      if (how < BUFFER_SIZE * blocksize) {
	 if (ferror(FROMF) != 0) {
	    perror("fread");
	    return 1;
	 }
	 if (bare_flag == FALSE) {
	    mhash(tm, ciphertext, how);
         }
         
	 if (mcrypt_enc_is_block_mode(td) == 1) {
	    rest_blocks = how % blocksize;
	    full_blocks = how / blocksize;
	    enc_bytes = full_blocks * blocksize;

	    mcrypt_generic(td, ciphertext, enc_bytes);

	    if (fwrite(ciphertext, 1, (enc_bytes), TOF) != (enc_bytes)) {
	       perror("fwrite");
	       return 1;
	    }

	 } else {		/* stream mode */
	    mcrypt_generic(td, ciphertext, how);
	    if (fwrite(ciphertext, 1, how, TOF) != how) {
	       perror("fwrite");
	       return 1;
	    }
	 }
	 if (flush == TRUE)
	    fflush(TOF);
	 break;
      }
      /* crc32 */
      if (bare_flag == FALSE) {
	 mhash(tm, ciphertext, how);
      }
      
      mcrypt_generic(td, ciphertext, how);

      if (fwrite(ciphertext, 1, how, TOF) != how) {
	 perror("fwrite");
	 return 1;
      }
      if (flush == TRUE)
	 fflush(TOF);
   }

   if (bare_flag == FALSE)
      fcrc32 = mhash_end(tm);

   if (bare_flag == FALSE) {
      pad_size = make_mult(rest_blocks + hash_size + 1, blocksize);

      /* in case of a stream cipher no padding is needed */
      if (mcrypt_enc_is_block_mode(td) == 0) {
	 pad_size = hash_size;
      }
   } else {			/* bare_flag==TRUE */
      pad_size = blocksize;
      if (mcrypt_enc_is_block_mode(td) == 0) {
	 pad_size = 0;
      }
   }

   if (pad_size > 0) {
      ciphertext_pad = _mcrypt_malloc(pad_size);
      if (ciphertext_pad == NULL)
	 err_quit(_("Memory error\n"));
   }
   if (mcrypt_enc_is_block_mode(td) == 1) {
      memmove(ciphertext_pad,
	      &ciphertext[full_blocks * blocksize], rest_blocks);
      if (bare_flag == FALSE) {
	 memmove(&ciphertext_pad[rest_blocks], fcrc32, hash_size);
	 ciphertext_pad[pad_size - 1] =
	     (unsigned char) blocksize - (pad_size -
					  hash_size - rest_blocks);
      } else {
	 ciphertext_pad[pad_size - 1] = (unsigned char) rest_blocks;
      }
   } else {
      if (bare_flag == FALSE)
	 memmove(ciphertext_pad, fcrc32, hash_size);
   }

   if (pad_size > 0) {
      mcrypt_generic(td, ciphertext_pad, pad_size);

      if (fwrite(ciphertext_pad, 1, pad_size, TOF) != pad_size) {
	 perror("fwrite");
	 return 1;
      }
   }

   /* if bare_flag==FALSE */
   /* End of copy */
   /* close files */
   fflush(TOF);

   if (stream_flag == FALSE) {
      fflush(FROMF);
      fflush(TOF);

   }
   fclose(TOF);

#ifdef ZIP
   if (gzipflag == FALSE && bzipflag == FALSE) {
#endif
      fclose(FROMF);
#ifdef ZIP
   } else {
      pclose(FROMF);
   }
#endif
/* Ready */

   mcrypt_generic_end(td);
   _mcrypt_end_timer();

   if (bare_flag == FALSE) {
      _mcrypt_free(salt);
   }

   _secure_mcrypt_free(keyword, keylen);
   _mcrypt_free(ciphertext);

   print_enc_info( fromfile, tofile);

   _mcrypt_time_show_stats(file_sum);

   return 0;
}



/* General Decryption */

int
decrypt_general(char *algorithm, char *fromfile, char *tofile, char *key)
{
   char *fcrc32, *newcrc32;
   MHASH tm = 0;
   char tmp_buf[BUFFER_SIZE];
   int how = 0;
   int i = 0;
   int blocksize, crcsize, salt_size;
   MCRYPT td;
   int pid, buf_block, start;
   word32 *IV = NULL;
   byte *ciphertext;
   byte *ciphertext_old, *ciphertext_p_old;
   word32 *keyword;
   word32 *salt;
   char local_algorithm[50], *command=NULL;
   char local_mode[50];
   char local_keymode[50];
   char local_salt[100];
   unsigned int len = 0;
   int hash_size, pad_size, clen;
   int j;
   FILE *RTOF;
   FILE *FROMF;
   size_t file_sum = 0;


/* open files */
   if (stream_flag == TRUE) {
      FROMF = stdin;
      RTOF = stdout;
#ifdef ZIP
      if (bzipflag == TRUE || gzipflag == TRUE) {
         err_info( "Will decompress input file.\n");
	 clen = 10;
	 if (fromfile != NULL)
	    clen += strlen(fromfile);

	 if (gzipflag == TRUE) {
	    clen += strlen(GZIP);
	    command = _mcrypt_malloc(clen);
	    strcpy(command, GZIP);
	 }
	 if (bzipflag == TRUE) {
	    clen += strlen(BZIP2);
	    command = _mcrypt_malloc(clen);
	    strcpy(command, BZIP2);
	 }
	 strcat(command, " -c -d ");
	 if (fromfile != NULL)
	    strcat(command, fromfile);

	 ppopen(command, &RTOF, NULL);

	 if (RTOF == NULL) {
	    err_crit("ppopen error\n");
	    return -1;
	 }
      }
#endif
   } else {
      FROMF = fopen(fromfile, "rb");
      if (FROMF == NULL) {
	 perror("fopen");
	 return 1;
      }

      RTOF = fopen(tofile, "wb");
      if (RTOF == NULL) {
	 perror("fopen");
	 return -1;
      }

   }


   if (bare_flag == FALSE) {
      if (check_file_head
	  (FROMF, local_algorithm, local_mode, local_keymode,
	   &keysize, local_salt, &salt_size) != 0) {
	 err_crit(_("No valid file headers found.\n"));
	 return 1;
      }
      salt = _mcrypt_malloc(salt_size);
      memmove(salt, local_salt, salt_size);
      algorithm = _mcrypt_malloc(strlen(local_algorithm) + 1);
      strcpy(algorithm, local_algorithm);
      mode = _mcrypt_malloc(strlen(local_mode) + 1);
      strcpy(mode, local_mode);
      keymode = _mcrypt_malloc(strlen(local_keymode) + 1);
      strcpy(keymode, local_keymode);
   } else {
      salt = NULL;
   }

   hash_size = mhash_get_block_size(hash_algorithm);

   td = mcrypt_module_open(algorithm, algorithms_directory, mode,
			   modes_directory);
   if (td == MCRYPT_FAILED) {
      err_crit(_("Mcrypt failed to open module.\n"));
      return 1;
   }

   if (keysize == 0)
      keysize = mcrypt_enc_get_key_size(td);


   blocksize = mcrypt_enc_get_block_size(td);

   ciphertext = _mcrypt_malloc(blocksize * BUFFER_SIZE);
   ciphertext_old = _mcrypt_malloc(blocksize);


/* Get key */

   if (key == NULL) {
      keyword =
	  fixkey(NULL, &len, keymode, keysize, quiet,
		 stream_flag, salt, salt_size, DECRYPT);
   } else {
      len = strlen(key);
      keyword =
	  fixkey(key, &len, keymode, keysize, quiet,
		 stream_flag, salt, salt_size, DECRYPT);
   }
   if (keyword == NULL) {
      err_crit("There was an error in key generation\n");
      return 1;
   }

   if (_mcrypt_iv_is_needed(td, mode, noiv) != 0) {
      IV = read_iv(FROMF, mcrypt_enc_get_iv_size(td));
   } else {
      IV = _mcrypt_calloc(1, mcrypt_enc_get_iv_size(td));
   }

#ifdef DEBUG
   fprintf(stderr, "IV: ");
   for (i = 0; i < mcrypt_get_iv_size(td); i++) {
      fprintf(stderr, "%.2x.", ((unsigned char *) IV)[i]);
   }
   fprintf(stderr, "\n");
#endif

   _mcrypt_start_timer();
   
   j = mcrypt_generic_init(td, keyword, len, IV);
   if (j < 0) {
      mcrypt_perror(j);
      return 1;
   }

   if (bare_flag == FALSE) {
      tm = mhash_init(hash_algorithm);
      if (tm==NULL)
         err_quit(_("mhash initialization failed.\n"));
   }

   crcsize = hash_size;
   fcrc32 = _mcrypt_malloc(crcsize);

   /* decryption starts here */

   if (bare_flag == FALSE) {
      pad_size = make_mult(blocksize + hash_size, blocksize);

      /* in case of a stream cipher no padding is needed */
      if (mcrypt_enc_is_block_mode(td) == 0) {
	 pad_size = hash_size;
      }

      ciphertext_p_old = _mcrypt_malloc(pad_size);
   } else {
      pad_size = 0;
      ciphertext_p_old = NULL;
   }

   if (mcrypt_enc_is_block_mode(td) == 1) {
      if (bare_flag == FALSE) {
	 how = fread(ciphertext, 1, blocksize * BUFFER_SIZE, FROMF);
	 file_sum += how;

	 if (pad_size > how)
	    pad_size -= blocksize;
	 how -= pad_size;
	 memmove(ciphertext_p_old, &ciphertext[how], pad_size);

	 mdecrypt_generic(td, ciphertext, how);

	 for (;;) {

	    if (how != blocksize * BUFFER_SIZE - pad_size) {
	       if (ferror(FROMF) != 0) {
		  perror("fread");
		  return 1;
	       }

	       if (how >= 0) {
		  if (how > 0) {
		     mhash(tm, ciphertext, how);
		     if (fwrite(ciphertext, 1, how, RTOF) != how) {
			perror("fread");
			return 1;
		     }
		  }

		  mdecrypt_generic(td, ciphertext_p_old, pad_size);

		  how = blocksize - ciphertext_p_old[pad_size - 1];
		  if (how > blocksize) {
		     err_warn(_("Corrupted file.\n"));
		     return 1;
		  }

		  mhash(tm, ciphertext_p_old, pad_size - how - hash_size);
		  if (fwrite(ciphertext_p_old, 1,
			     pad_size - how -
			     hash_size,
			     RTOF) != pad_size - how - hash_size) {
		     perror("fwrite");
		     return 1;
		  }
		  if (flush == TRUE)
		     fflush(RTOF);

		  memmove(fcrc32,
			  &ciphertext_p_old
			  [pad_size - how - hash_size], hash_size);
	       } else {
		  fprintf(stderr, _("Unexpected error [%d]\n"), how);
		  return 1;
	       }
	       break;
	    }

	    mhash(tm, ciphertext, how);

	    if (fwrite(ciphertext, 1, how, RTOF) != how) {
	       perror("fwrite");
	       return 1;
	    }

	    if (flush == TRUE)
	       fflush(RTOF);

	    memmove(ciphertext, ciphertext_p_old, pad_size);
	    how =
		fread(&ciphertext[pad_size], 1,
		      blocksize * BUFFER_SIZE - pad_size, FROMF);
	    file_sum += how;

	    mdecrypt_generic(td, ciphertext, how);
	    memmove(ciphertext_p_old, &ciphertext[how], pad_size);

	 }
      } else {			/* bare flag == TRUE */

	 buf_block = BUFFER_SIZE * blocksize;
	 start = 0;
	 for (;;) {

	    how = fread(ciphertext, 1, buf_block, FROMF);
	    file_sum += how;

	    if (how == buf_block && start == 1) {
	       if (fwrite(ciphertext_old, 1, blocksize, RTOF) != blocksize) {
		  perror("fwrite");
		  return 1;
	       }
	       if (flush == TRUE)
		  fflush(RTOF);

	    }

	    mdecrypt_generic(td, ciphertext, how);

	    if (how != buf_block) {
	       if (ferror(FROMF) != 0) {
		  perror("fread");
		  return 1;
	       }

	       if (how % blocksize != 0) {
		  err_crit(_("Corrupted file.\n"));
		  return 1;
	       }
	       if (how == 0) {
		  if (start != 0) {
		     if (fwrite
			 (ciphertext_old,
			  1,
			  ciphertext_old
			  [blocksize -
			   1], RTOF) != ciphertext_old[blocksize - 1]) {
			perror("fwrite");
			return 1;
		     }
		  }
		  if (flush == TRUE)
		     fflush(RTOF);

	       } else {		/* how > 0 > blocksize */
		  if (start != 0) {
		     if (fwrite
			 (ciphertext_old,
			  1, blocksize, RTOF) != blocksize) {
			perror("fwrite");
			return 1;
		     }
		  }
		  if (fwrite
		      (ciphertext, 1,
		       how - blocksize, RTOF) != how - blocksize) {
		     perror("fwrite");
		     return 1;
		  }
		  if (flush == TRUE)
		     fflush(RTOF);

		  if (fwrite
		      (&ciphertext
		       [how - blocksize], 1,
		       ciphertext[how - 1], RTOF) != ciphertext[how - 1]) {
		     perror("fwrite");
		     return 1;
		  }
		  if (flush == TRUE)
		     fflush(RTOF);

	       }
	       break;
	    }

	    memmove(ciphertext_old,
		    &ciphertext[buf_block - blocksize], blocksize);

	    start = 1;

	    if (fwrite
		(ciphertext, 1, buf_block - blocksize,
		 RTOF) != buf_block - blocksize) {
	       perror("fwrite");
	       return 1;
	    }

	    if (flush == TRUE)
	       fflush(RTOF);

	 }

      }
   } else {			/* stream */
      if (bare_flag == FALSE) {
	 for (;;) {
	    how = fread(ciphertext, 1, BUFFER_SIZE, FROMF);
	    file_sum += how;
	    mdecrypt_generic(td, ciphertext, how);

	    if (how != BUFFER_SIZE) {
	       if (ferror(FROMF) != 0) {
		  perror("fread");
		  return 1;
	       }
	       if (how < hash_size) {
		  memmove(fcrc32,
			  &tmp_buf
			  [BUFFER_SIZE -
			   hash_size + how], hash_size - how);
		  memmove(&fcrc32[hash_size - how], ciphertext, how);
	       } else {
		  memmove(fcrc32, &ciphertext[how - hash_size], hash_size);
	       }

	       if (how > hash_size) {
		  mhash(tm, ciphertext, how - hash_size);
		  if (fwrite
		      (ciphertext, 1,
		       how - hash_size, RTOF) != how - hash_size) {
		     perror("fwrite");
		     return 1;
		  }
		  if (flush == TRUE)
		     fflush(RTOF);

	       }
	       break;
	    }

	    memmove(tmp_buf, ciphertext, BUFFER_SIZE);
	    mhash(tm, ciphertext, BUFFER_SIZE);

	    if (fwrite(ciphertext, 1, BUFFER_SIZE, RTOF) != BUFFER_SIZE) {
	       perror("fwrite");
	       return 1;
	    }

	    if (flush == TRUE)
	       fflush(RTOF);

	 }
      } else {			/* bare flag == TRUE */

	 for (;;) {

	    how = fread(ciphertext, 1, BUFFER_SIZE, FROMF);
	    file_sum += how;
	    mdecrypt_generic(td, ciphertext, how);

	    if (how != BUFFER_SIZE) {
	       if (ferror(FROMF) != 0) {
		  perror("fread");
		  return 1;
	       }
	       if (fwrite(ciphertext, 1, how, RTOF) != how) {
		  perror("fwrite");
		  return 1;
	       }
	       if (flush == TRUE)
		  fflush(RTOF);
	       break;
	    }

	    if (fwrite(ciphertext, 1, BUFFER_SIZE, RTOF) != BUFFER_SIZE) {
	       perror("fwrite");
	       return 1;
	    }

	    if (flush == TRUE)
	       fflush(RTOF);

	 }
      }
   }


/* close files */

   if (stream_flag == FALSE) {
      fflush(FROMF);
      fflush(RTOF);
   }
   fclose(RTOF);
   fclose(FROMF);

/* ready */

   if (pad_size > 0) {
      Bzero(ciphertext_p_old, pad_size);
      _mcrypt_free(ciphertext_p_old);
   }
   Bzero(ciphertext_old, blocksize);
   Bzero(ciphertext, blocksize * BUFFER_SIZE);

   _mcrypt_free(ciphertext_old);
   _mcrypt_free(ciphertext);

   Bzero(tmp_buf, BUFFER_SIZE);
   _secure_mcrypt_free(keyword, keysize);

   if (bare_flag == FALSE) {
      newcrc32 = mhash_end(tm);
      if (mcrypt_enc_is_block_mode(td) == 1) {
	 if (hash_size > blocksize) {
	    hash_size = blocksize;
	 }
      }

      if (memcmp(newcrc32, fcrc32, hash_size) == 0) {
#ifdef ZIP
	 if (stream_flag == FALSE
	     && (gzipflag == TRUE || bzipflag == TRUE)) {

	    pid = fork();
	    if (pid == 0) {
	       if (gzipflag == TRUE) {
		  err_warn(_("Decompressing the output file...\n"));
		  i = execlp(GZIP, GZIP, "-d", tofile, NULL);
		  if (i == -1) {
		     perror("exec");
		     return 1;
		  }

	       }
	       if (bzipflag == TRUE) {
		  err_warn(_("Decompressing the output file...\n"));
		  i = execlp(BZIP2, BZIP2, "-d", tofile, NULL);
		  if (i == -1) {
		     perror("exec");
		     return 1;
		  }

	       }
	    }
#ifdef HAVE_WAITPID
	    waitpid(pid, NULL, 0);
#endif
	    if (bzipflag == TRUE) {
	       tofile[strlen(tofile) - strlen(".bz2")] = '\0';
	    } else {
	       tofile[strlen(tofile) - strlen(".gz")] = '\0';
	    }
	 }
#endif
	 /* crc check passed */

      } else {
	 command = mhash_get_hash_name(hash_algorithm);
	 fprintf(stderr, _("%s check failed\n"), command);
	 return 1;		/* CRC32s Do not match */
      }
   }

   mcrypt_generic_end(td);
   _mcrypt_end_timer();
   
   print_enc_info( fromfile, tofile);

   _mcrypt_time_show_stats(file_sum);

   return 0;


}




/* Rols the buffer by one byte and puts the value in the empty cell */

void rol_buf(void *buffer, int buffersize, void *value)
{
   char *buf = buffer;
   char *val = value;
   int i;

   for (i = 0; i < buffersize - 1; i++) {
      buf[i] = buf[i + 1];
   }
   buf[buffersize - 1] = val[0];
}

int print_list(void)
{
   MCRYPT td;
   int i, imax;
   int j, jmax;
   int start;
   char **names;
   char **modes;


   names = mcrypt_list_algorithms(algorithms_directory, &jmax);
   if (names == NULL) {
      if (algorithms_directory == NULL)
	 algorithms_directory = "default directory";
      fprintf(stderr, "Could not find algorithms in %s\n",
	      algorithms_directory);
      exit(1);
   }
   modes = mcrypt_list_modes(modes_directory, &imax);
   if (modes == NULL) {
      if (modes_directory == NULL)
	 modes_directory = "default directory";
      fprintf(stderr, "Could not find modes in %s\n", modes_directory);
      exit(1);
   }

   for (j = 0; j < jmax; j++) {
      printf("%s ", names[j]);
      start = 0;

      for (i = 0; i < imax; i++) {
	 td = mcrypt_module_open(names[j],
				 algorithms_directory,
				 modes[i], modes_directory);

	 if (td != MCRYPT_FAILED) {
	    if (start == 0)
	       printf("(%d): ", mcrypt_enc_get_key_size(td));
	    printf("%s ", modes[i]);
	    mcrypt_module_close(td);
	    start = 1;
	 }
      }
      printf("\n");
   }

   mcrypt_free_p(names, jmax);
   mcrypt_free_p(modes, imax);
   return 0;
}

int print_keylist(void)
{

   printf("asis\n");
   printf("scrypt\n");
   printf("mcrypt-md5\n");
   printf("mcrypt-sha1\n");
   printf("hex\n");
   printf("pkdes\n");
   printf("s2k-simple-md5\n");
   printf("s2k-simple-sha1\n");
   printf("s2k-simple-ripemd\n");
   printf("s2k-salted-md5\n");
   printf("s2k-salted-sha1\n");
   printf("s2k-salted-ripemd\n");
   printf("s2k-isalted-md5\n");
   printf("s2k-isalted-sha1\n");
   printf("s2k-isalted-ripemd\n");

   return 0;
}

int print_hashlist(void)
{
   int tmpi;
   char *tmpc;
   char tmp[255];

   fprintf(stdout, _("Supported Hash Algorithms:\n"));
   for (tmpi = 0; tmpi < 256; tmpi++) {
      tmpc = mhash_get_hash_name(tmpi);
      if (tmpc != NULL) {
	 strcpy(tmp, tmpc);
	 mcrypt_tolow(tmp, strlen(tmp));
	 fprintf(stdout, "%s\n", tmp);
      }
   }
   return 0;
}

