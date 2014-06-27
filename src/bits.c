/*
 *    Copyright (C) 1998,1999,2000,2007 Nikos Mavroyanopoulos
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

/* $Id: bits.c,v 1.2 2007/11/07 17:10:18 nmav Exp $ */

#ifndef DEFINES_H
#define DEFINES_H
#include <defines.h>
#endif
#include "bits.h"
#include <extra.h>		/* for MAX_KEY_LEN */



unsigned int m_setbit(unsigned int which, unsigned int fullnum, unsigned int what)
{
	if (what == 1) {
		return i_setbit(which, fullnum);
	} else {
		return i_unsetbit(which, fullnum);
	}
}


