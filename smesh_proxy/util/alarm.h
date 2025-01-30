
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


#ifndef INC_ALARM
#define INC_ALARM

#include <stdio.h>
#include "arch.h"

#define		DEBUG		0x00000001
#define 	EXIT  		0x00000002
#define		PRINT		0x00000004

#define		DATA_LINK	0x00000010
#define		NETWORK		0x00000020
#define		PROTOCOL	0x00000040
#define		SESSION		0x00000080
#define		CONF		0x00000100
#define		MEMB		0x00000200
#define		FLOW_CONTROL	0x00000400
#define		STATUS		0x00000800
#define		EVENTS		0x00001000
#define		GROUPS		0x00002000

#define         HOP             0x00004000
#define         OBJ_HANDLER     0x00008000
#define         MEMORY          0x00010000
#define         ROUTE           0x00020000
#define         QOS             0x00040000
#define         RING            0x00080000
#define         TCP_HOP         0x00100000

#define         SKIPLIST        0x00200000
#define         ACM             0x00400000

#define		ALL		0xffffffff
#define		NONE		0x00000000


#ifdef  HAVE_GOOD_VARGS
void Alarm( int32 mask, char *message, ...);

#else
void Alarm();
#endif

void Alarm_set_output(char *filename);

void Alarm_enable_timestamp(char *format);
void Alarm_disable_timestamp(void);

void Alarm_set(int32 mask);
void Alarm_clear(int32 mask);
int32 Alarm_get(void);

void Alarm_set_interactive(void);
int  Alarm_get_interactive(void);

#define IP1( address )  ( ( 0xFF000000 & (address) ) >> 24 )
#define IP2( address )  ( ( 0x00FF0000 & (address) ) >> 16 )
#define IP3( address )  ( ( 0x0000FF00 & (address) ) >> 8 )
#define IP4( address )  ( ( 0x000000FF & (address) ) )
#define IP( address ) IP1(address),IP2(address),IP3(address),IP4(address)
#define IPF "%d.%d.%d.%d"


#endif	/* INC_ALARM */
