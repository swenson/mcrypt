/*
 *    Copyright (C) 1998,1999,2000 Nikos Mavroyanopoulos
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

/* $Id: errors.c,v 1.2 2007/11/07 17:10:19 nmav Exp $ */

#include <stdio.h>
#include <stdlib.h>

extern int quiet;

void err_quit(char *errmsg)
{
	fprintf(stderr, errmsg);
	exit(-1);
}

void err_warn(char *errmsg)
{
	if (quiet <= 1)
		fprintf(stderr, errmsg);
}

void err_info(char *errmsg)
{
	if (quiet == 0)
		fprintf(stderr, errmsg);
}

void err_crit(char *errmsg)
{
	if (quiet <= 2)
		fprintf(stderr, errmsg);
}
