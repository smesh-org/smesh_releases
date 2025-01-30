/*
 * The Spread Toolkit.
 *     
 * The contents of this file are subject to the Spread Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spread.org/license/
 *
 * or in the file ``license.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Spread are:
 *  Yair Amir, Michal Miskin-Amir, Jonathan Stanton.
 *
 *  Copyright (C) 1993-2003 Spread Concepts LLC <spread@spreadconcepts.com>
 *
 *  All Rights Reserved.
 *
 * Major Contributor(s):
 * ---------------
 *    Cristina Nita-Rotaru crisn@cnds.jhu.edu - group communication security.
 *    Theo Schlossnagle    jesus@omniti.com - Perl, skiplists, autoconf.
 *    Dan Schoenblum       dansch@cnds.jhu.edu - Java interface.
 *    John Schultz         jschultz@cnds.jhu.edu - contribution to process group membership.
 *
 *
 * This file is also licensed by Spread Concepts LLC under the Spines 
 * Open-Source License, version 1.0. You may obtain a  copy of the 
 * Spines Open-Source License, version 1.0  at:
 *
 * http://www.spines.org/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 */



#include "arch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_GOOD_VARGS
#include <stdarg.h>
#endif

#include "alarm.h"

static int32	Alarm_mask = PRINT | EXIT ;
/*static int32	Alarm_mask = EXIT ;*/

static char     *Alarm_timestamp_format = NULL;

static const char *DEFAULT_TIMESTAMP_FORMAT="[%a %d %b %Y %H:%M:%S]";

static int      AlarmInteractiveProgram = FALSE;

#ifdef HAVE_GOOD_VARGS

/* Probably should work on all platforms, but just in case, I leave it to the
   developers...
*/

void Alarm( int32 mask, char *message, ...)
{
	if ( Alarm_mask & mask )
        {
	    va_list ap;

	    if ( Alarm_timestamp_format )
            {
	        char timestamp[42];
		struct tm *tm_now;
		time_t time_now;
		size_t length;
		
		time_now = time(NULL);
		tm_now = localtime(&time_now);
		length = strftime(timestamp, 40,
				  Alarm_timestamp_format, tm_now);
		timestamp[length] = ' ';
		fwrite(timestamp, length+1, sizeof(char), stdout);
            }

	    va_start(ap,message);
	    vprintf(message, ap);
	    va_end(ap);
	    fflush(stdout);
        }

	if ( EXIT & mask )
	{
#ifndef	_WIN32_WCE
	    perror("errno say:");
#endif
	    /* Uncoment the next line if you want to coredump on exit */
		abort();
	       	exit( 0 );
	}
}

#else

void Alarm( int32 mask, char *message, 
                        void *ptr1, void *ptr2, void *ptr3, void *ptr4, 
                        void *ptr5, void *ptr6, void *ptr7, void *ptr8,
                        void *ptr9, void *ptr10, void*ptr11, void *ptr12,
                        void *ptr13, void *ptr14, void *ptr15, void *ptr16,
                        void *ptr17, void *ptr18, void *ptr19, void *ptr20)
{
//#ifndef _WIN32_WCE
	if ( Alarm_mask & mask )
        {
            if ( Alarm_timestamp_format )
            {
		char timestamp[42];
		struct tm *tm_now;
		time_t time_now;
		size_t length;
		
#ifndef _WIN32_WCE
		time_now = time(NULL);
		tm_now = localtime(&time_now);
		length = strftime(timestamp, 40,
				  Alarm_timestamp_format, tm_now);
#endif
		timestamp[length] = ' ';
		fwrite(timestamp, length+1, sizeof(char), stdout);
            }
	    printf(message, ptr1, ptr2, ptr3, ptr4, ptr5, ptr6, ptr7, ptr8, ptr9, ptr10, ptr11, ptr12, ptr13, ptr14, ptr15, ptr16, ptr17, ptr18, ptr19, ptr20 );

        }
//#endif

	if ( EXIT & mask )
	{
#ifndef _WIN32_WCE
		perror("errno say:");
#endif
		/*abort();*/
	    exit( 0 );
	}
}

#endif /* HAVE_GOOD_VARGS */

void Alarm_set_interactive(void) 
{
        AlarmInteractiveProgram = TRUE;
}

int  Alarm_get_interactive(void)
{
        return(AlarmInteractiveProgram);
}

void Alarm_set_output(char *filename) {
        FILE *newfile;

        newfile = freopen(filename, "a", stdout);
#ifndef	_WIN32_WCE
        if ( NULL == newfile ) {
			perror("failed to open file for stdout");
		}
#endif
        newfile = freopen(filename, "a", stderr);
#ifndef	_WIN32_WCE
        if ( NULL == newfile ) {
                perror("failed to open file for stderr");
        }
#endif

        setvbuf(stderr, (char *)0, _IONBF, 0);
        setvbuf(stdout, (char *)0, _IONBF, 0);
}

void Alarm_enable_timestamp(char *format)
{
        static char _local_timestamp[40];
	if(format)
	  strncpy(_local_timestamp, format, 40);
	else
	  strncpy(_local_timestamp, DEFAULT_TIMESTAMP_FORMAT, 40);
        Alarm_timestamp_format = _local_timestamp;
}

void Alarm_disable_timestamp(void)
{
        Alarm_timestamp_format = NULL;
}

void Alarm_set(int32 mask)
{
	Alarm_mask = Alarm_mask | mask;
}

void Alarm_clear(int32 mask)
{
	Alarm_mask = Alarm_mask & ~mask;
}

int32 Alarm_get(void)
{
        return(Alarm_mask);
}
