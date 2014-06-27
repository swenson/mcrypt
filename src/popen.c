/*
 *    Copyright (C) 2000 Stefan Hetzl <shetzl@teleweb.at>
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


/* This function is made by: Stefan Hetzl <shetzl@teleweb.at>
 * Some changes to use in mcrypt by nmav.
 */

#include <defines.h>
#include <xmalloc.h>

#ifdef ZIP

/* function ppopen
 * int ppopen (const char *command, FILE **ch_stdin, FILE **ch_stdout)
 * arguments: command    command to execute (with arguments)
 *            ch_stdin   stdin of forked process (command) 
 *            ch_stdout  stdout of forked process (command)
 * return value: pid of forked process
 */
#define CHILD_ARGCMAX	20
#define CHILD_ARGLENMAX 512
int ppopen (const char *command, FILE **ch_stdin, FILE **ch_stdout)
{
	int pchin[2] = {-1, -1} ;
	int pchout[2] = {-1, -1} ;
	int pid = -1 ;
	int i = 0, j = 0, argc = 0 ;
	char *argv[CHILD_ARGCMAX + 1] ;

	if (ch_stdout!=NULL) *ch_stdout = NULL;
	if (ch_stdin!=NULL) *ch_stdin = NULL;
	
	/* parse command to create argc and argv */
	while (command[i] != '\0') {
		argv[argc] = _mcrypt_malloc (CHILD_ARGLENMAX);

		j = 0 ;
		while ((command[i] != ' ') && (command[i] != '\t') && (command[i] != '\"') && (command[i] != '\0'))
			argv[argc][j++] = command[i++] ;
		argv[argc][j] = '\0' ;

		if ((command[i] == ' ') || (command[i] == '\t')) {
			while ((command[i] == ' ') || (command[i] == '\t'))
				i++ ;
		}
		else if (command[i] == '\"') {
			if (j != 0) {
				/* for example: cat foo"bar */
				fprintf (stderr, _("command string is not correct!\n"));
			}
			i++ ;
			while (command[i] != '\"')
				argv[argc][j++] = command[i++] ;
			argv[argc][j] = '\0' ;

			i++ ;
			if ((command[i] != ' ') && (command[i] != '\t') && (command[i] != '\0')) {
				/* for example: cat "foo"bar */
				fprintf (stderr, _("command string is not correct!\n"));
			}
			while ((command[i] == ' ') || (command[i] == '\t'))
				i++ ;
		}

		argc++ ;
	}

	argv[argc] = NULL ;

	/* create pipes (used for stdin/stdout) */
	if (pipe (pchin) == -1)
		fprintf (stderr, _("could not create pipe\n"));

	if (pipe (pchout) == -1)
		fprintf (stderr, _("could not create pipe\n"));

	/* fork child process */
	switch (pid = fork()) {
		case -1: /* error */
			fprintf (stderr, _("could not fork child process\n"));
		break ;

		case 0: /* child */
			/* assign pipes to stdin and stdout */
			if (ch_stdin!=NULL) {
				if (close (pchin[1]) == -1)
					fprintf (stderr, _("could not close write-access of child stdin!\n"));
				if (dup2 (pchin[0], STDIN_FILENO) == -1)
					fprintf (stderr, _("could not dup2 child stdin!\n"));
				if (close (pchin[0]) == -1)
					fprintf (stderr, _("could not close read-access of child stdin!\n"));
			}
			
			if (ch_stdout!=NULL) {
				if (close (pchout[0]) == -1)
					fprintf (stderr, _("could not close read-access of child stdout!\n"));
				if (dup2 (pchout[1], STDOUT_FILENO) == -1)
					fprintf (stderr, _("could not dup2 child stdout!\n"));
				if (close (pchout[1]) == -1)
					fprintf (stderr, _("could not close write-access of child stdout!\n"));
			}
			 execvp (argv[0], argv) ;
		break ;

		default: /* parent */
			if (ch_stdin!=NULL) {
				if (close (pchin[0]) == -1)
					fprintf (stderr, _("could not close read-access of child stdin!\n"));
				if ((*ch_stdin = fdopen (pchin[1], "w")) == NULL)
					fprintf (stderr, _("could not fdopen child stdin pipe!\n"));
			}
			if (ch_stdout!=NULL) {
				if (close (pchout[1]) == -1)
					fprintf (stderr, _("could not close write-access of child stdout!\n"));
				if ((*ch_stdout = fdopen (pchout[0], "r")) == NULL)
					fprintf (stderr, _("could not fdopen child stdout pipe!\n"));
			}
		break ;
	}

	return pid ;
}

#endif /* ZIP */
