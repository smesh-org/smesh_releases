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



/* errors.h
 * Copyright (c) 1997 Jonathan Stanton <jonathan@cs.jhu.edu>
 * Defines all Error codes used in spread
 *
 * $Id: errors.h,v 1.1.1.1 2006/08/22 13:26:37 nrivera Exp $
 *
 */

#ifndef ERRORS_H
#define ERRORS_H

#define OK                      1       /* All OK */

#define ERR_EMPTY               -5      /* Data structure is empty */
#define ERR_NOTFOUND            -6      /* Specified entry not found in data structure */
#define ERR_NOMEM               -7      /* No memory available */

/************************************
 * Protocol return codes
 ************************************/

#define MSG_COMPLETE            2
#define ERR_BREAK               -10

/************************************ 
 * Errors for Links
 ************************************/
#define LINK_LS_NOTPRESENT      -40
#define LINK_FAIL               -41
#define LINK_NOTAVAIL           -42
#define LINK_INVALID            -43
#define SELF_LINK               -44

/************************************
 * Error codes for memory functions
 ************************************/
#define MEM_ERR                 -51     /* Unknown error occured in memory (d)alloc check perror */

/************************************
 * Object Errors
 ************************************/

#define OBJ_UNKNOWN             -100    /* Object type is unknown to function */


/************************************
 * Status Errors
 ************************************/

#define ERR_STAT_INSERT_FAILURE -200    /* Insert of record failed */
#define ERR_STAT_GROUP_FULL     -201    /* Reached maximum size of group of stat variables */
#define ERR_STAT_GROUP_EMPTY    -202    /* Stat group empty */
#define ERR_STAT_ILLEGAL_STATTYPE       -203    /* Not a valid datatype for a statistic */

#endif /* ERRORS_H */
