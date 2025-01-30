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



#ifndef INC_ARCH
#define INC_ARCH

#include <limits.h>
/*
 * Each record in this file represents an architecture.
 * Each record contains the following fields:
 *
 *	#define		INTSIZE{16,32,64}
 *	#define		ARCH_SCATTER_{CONTROL,ACCRIGHTS,NONE}
 *	#define		ARCH_ENDIAN{0x00000000,0x80000080}
 *      #define         LOC_INLINE { __inline__ or blank }
 *      #define         ARCH_SCATTER_SIZE { sys dependent variable }
 *      #define         HAVE_GOOD_VARGS ( exists if true )
 *      #define         HAVE_LRAND48 ( exists if true )
 *      #define         HAVE_STDINT_H   ( exists if true --currently glibc2.1 needs it )
 *      typedef         {sys dependent type} sockopt_len_t
 */


#ifdef __x86_64__
/* HACK TODO defined so that 64 bit AMD o Xeon will work */
#define ARCH_IA64_LINUX 1 
#endif


/* Permit the Microsoft Visual C compiler to use inline functions */
#ifdef _MSC_VER
#ifndef __cplusplus
#define inline __inline
#endif
#endif

#ifdef DEBUG
#undef DEBUG
#endif

#ifdef _WIN32_WCE
#define long64 __int64

/* Take care of some macros that are not defined in Microsoft eMbedded
Visual C */
#define EAGAIN 11
#define _IONBF 2

#define freopen _wfreopen

#else
typedef long long long64;
#endif /* _WIN32_WCE */

#ifdef __CYGWIN__
#define ARCH_PC_WIN95
#endif

#ifdef ARCH_MIPS_LINUX
#define ARCH_PC_LINUX
#endif

#ifdef _AIX
#ifdef _IBMR2
#ifdef _POWER
#define ARCH_POWER_AIX
#endif
#endif
#endif

#ifdef __alpha__
#ifdef __linux__
#define ARCH_ALPHA_LINUX
#endif
#endif /* __alpha__ */

#ifdef __ia64__
#ifdef __linux__
#define ARCH_IA64_LINUX
#endif
#endif /* __ia64__ */

#ifdef __i386__
#ifdef __bsdi__
#define ARCH_PC_BSDI
#endif

#ifdef __FreeBSD__
#if __FreeBSD__ == 4
#define ARCH_PC_FREEBSD4
#else
#define ARCH_PC_FREEBSD3
#endif
#endif

#ifdef __linux__
#define ARCH_PC_LINUX
#endif

#ifdef __svr4__
#define ARCH_PC_SOLARIS
#endif
#endif /* __i386__ */

#ifdef __ppc__
#ifdef __APPLE__
#ifdef __MACH__
#define ARCH_PPC_DARWIN
#endif
#endif
#endif

#ifdef __sparc__
#ifdef __svr4__
#define ARCH_SPARC_SOLARIS
#endif

#ifdef  __linux__
#define ARCH_SPARC_LINUX
#endif

#ifdef  __sun__
#ifndef __svr4__
#define ARCH_SPARC_SUNOS
#endif
#endif

#endif	/* __sparc__ */

#ifdef __sgi
#define ARCH_SGI_IRIX
#endif

#undef          INTSIZE32
#undef          INTSIZE64
#undef          INTSIZE16


#ifdef ARCH_POWER_AIX
#define		INTSIZE32
#define		ARCH_SCATTER_CONTROL
#define		ARCH_ENDIAN	0x00000000
/* Do not need accept, set/getsockopt defines */
#define         ARCH_SCATTER_SIZE       64 /* UNKNOWN -- Check value */
#define         HAVE_LRAND48
typedef         unsigned long  sockopt_len_t;
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_POWER_AIX */

#ifdef ARCH_ALPHA_LINUX
#define         INTSIZE64
#define		ARCH_SCATTER_CONTROL /* should be control if supported */
#define		ARCH_ENDIAN	0x80000080
#define         LOC_INLINE      __inline__
#include        <sys/uio.h>
#define         ARCH_SCATTER_SIZE       UIO_MAXIOV
#define         HAVE_GOOD_VARGS
#define         HAVE_LRAND48
typedef         int     sockopt_len_t;
/* Already defined in linux
   typedef         int     socklen_t;
*/
/* this define is needed for glibc2.1 but should be turned off for glibc2.0 and earlier. */
#define         HAVE_STDINT_H
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_ALPHA_LINUX */

#ifdef ARCH_IA64_LINUX
#define         INTSIZE64
#define		ARCH_SCATTER_CONTROL /* should be control if supported */
#define		ARCH_ENDIAN	0x80000080
#define         LOC_INLINE      __inline__
#include        <sys/uio.h>
#define         ARCH_SCATTER_SIZE       UIO_MAXIOV
#define         HAVE_GOOD_VARGS
#define         HAVE_LRAND48
typedef         int     sockopt_len_t;
/* Already defined in linux
   typedef         int     socklen_t;
*/
/* this define is needed for glibc2.1 but should be turned off for glibc2.0 and earlier. */
#define         HAVE_STDINT_H
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_ALPHA_LINUX */

#ifdef ARCH_PC_BSDI
#define         INTSIZE32
#define		ARCH_SCATTER_CONTROL
#define		ARCH_ENDIAN	0x80000080
#define         LOC_INLINE      __inline__
#include        <sys/types.h>
#include	<sys/uio.h>
#define         ARCH_SCATTER_SIZE       1024 /* Should be UIO_MAXIOV but there is a problem is sys/uio.h */
#define         HAVE_LRAND48
typedef         size_t  sockopt_len_t;
/* Already defined in BSDI
   typedef         int       socklen_t;
*/
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_PC_BSDI */

#ifdef ARCH_PC_FREEBSD4
#define		INTSIZE32
#define		ARCH_SCATTER_CONTROL
#define		ARCH_ENDIAN	0x80000080
#define         LOC_INLINE      __inline__
#include        <sys/types.h>
#include	<sys/uio.h>
#define         ARCH_SCATTER_SIZE       1024 /* should be UIO_MAXIOV but it isn't actually declared in system includes */
#define         HAVE_GOOD_VARGS
#define         HAVE_LRAND48
typedef         int     sockopt_len_t;
/* Already defined in freebsd 4.0
  typedef         u_int32_t   socklen_t;
*/
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_PC_FREEBSD */

#ifdef ARCH_PC_FREEBSD3
#define		INTSIZE32
#define		ARCH_SCATTER_CONTROL
#define		ARCH_ENDIAN	0x80000080
#define         LOC_INLINE      __inline__
#include        <sys/types.h>
#include	<sys/uio.h>
#define         ARCH_SCATTER_SIZE       1024 /* should be UIO_MAXIOV but it isn't actually declared in system includes */
#define         HAVE_GOOD_VARGS
#define         HAVE_LRAND48
typedef         int     sockopt_len_t;
typedef         u_int32_t   socklen_t;
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_PC_FREEBSD3 */

#ifdef ARCH_PC_LINUX
#define         INTSIZE32
#define		ARCH_SCATTER_CONTROL /* should be control if supported */
#define		ARCH_ENDIAN	0x80000080
#define         LOC_INLINE      __inline__
#include        <sys/uio.h>
#define         ARCH_SCATTER_SIZE       UIO_MAXIOV
#define         HAVE_GOOD_VARGS
#define         HAVE_LRAND48
typedef         int     sockopt_len_t;
/* Already defined in linux
   typedef         int     socklen_t;
*/
/* this define is needed for glibc2.1 but should be turned off for glibc2.0 and earlier. */
#define         HAVE_STDINT_H
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_PC_LINUX */

#ifdef ARCH_PPC_DARWIN
#define         INTSIZE32
#define         ARCH_SCATTER_CONTROL
#define         ARCH_ENDIAN     0x00000000
#define         LOC_INLINE      __inline__
#include        <sys/types.h>
#include        <sys/uio.h>
#define         ARCH_SCATTER_SIZE       1024 /* Should be UIO_MAXIOV when defining KERNEL before including uio.h */
#define         HAVE_GOOD_VARGS
typedef         int sockopt_len_t;
/*typedef         int socklen_t;*/
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif  /* ARCH_PPC_DARWIN */


#ifdef ARCH_PC_SOLARIS
#define         INTSIZE32
#define         ARCH_SCATTER_ACCRIGHTS
#define         ARCH_ENDIAN     0x80000080
#define         LOC_INLINE
#include        <sys/socket.h>
#define         ARCH_SCATTER_SIZE       MSG_MAXIOVLEN
#define         BSD_COMP
#define         HAVE_LRAND48
typedef         size_t  sockopt_len_t;
/* Already defined in solaris 5.7, maybe needed for earlier versions
   typedef         int     socklen_t;
*/
/* this define is needed for solaris 5.[67] but maybe should be turned off for earlier. */
#define         HAVE_SYS_INTTYPES_H
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif

#ifdef	ARCH_SPARC_SOLARIS
#define         INTSIZE32
#define		ARCH_SCATTER_ACCRIGHTS
#define		ARCH_ENDIAN	0x00000000
#define         LOC_INLINE
#include        <sys/socket.h>
#define         ARCH_SCATTER_SIZE       MSG_MAXIOVLEN
#define         BSD_COMP
#define         HAVE_LRAND48
typedef         size_t  sockopt_len_t;
/* Already defined in solaris 5.7, maybe needed for earlier versions
typedef         int     socklen_t;
*/
#define         HAVE_SYS_INTTYPES_H
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_SUN_UNIX */

#ifdef ARCH_SPARC_LINUX
#define         INTSIZE32
#define		ARCH_SCATTER_CONTROL /* should be control if supported */
#define		ARCH_ENDIAN	0x00000000
#define         LOC_INLINE      __inline__
#include        <sys/uio.h>
#define         ARCH_SCATTER_SIZE       UIO_MAXIOV
#define         HAVE_GOOD_VARGS
#define         HAVE_LRAND48
typedef         int     sockopt_len_t;
typedef         int     socklen_t;
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_SPARC_LINUX */

#ifdef	ARCH_SPARC_SUNOS
#define         INTSIZE32
#define		ARCH_SCATTER_NONE
#define		ARCH_ENDIAN	0x00000000
#define         LOC_INLINE
typedef         int     sockopt_len_t;
typedef         int     socklen_t;
/* HACKS to fix OS bugs */
#define         RAND_MAX        2147483647
/* This size is for packing several messages into one packet */
#define         ARCH_SCATTER_SIZE       64
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_SPARC_SUNOS */

#ifdef ARCH_SGI_IRIX
#define         INTSIZE32
#define		ARCH_SCATTER_ACCRIGHTS
#define		ARCH_ENDIAN	0x00000000
#define         LOC_INLINE
/* Irix only appears to define IOV_MAX through the runtime
 * function 'sysconf' and does not have an includeable variable
 * as best as I can tell. The man page says all irix have at
 * least 512
 */
#define         ARCH_SCATTER_SIZE       512
#define         HAVE_LRAND48
typedef         int     sockopt_len_t;
typedef         int     socklen_t;
#define         ERR_TIMEDOUT    ETIMEDOUT
#endif /* ARCH_SGI_UNIX */

#ifdef ARCH_PC_WIN95
#define         INTSIZE32
#define		ARCH_SCATTER_NONE
#define		ARCH_ENDIAN	0x80000080
#define         LOC_INLINE
typedef         unsigned long   sockopt_len_t;
#define         BADCLOCK
/* This size is for packing several messages into one packet */
#define         ARCH_SCATTER_SIZE       64
#define         ERR_TIMEDOUT    EAGAIN
#define         snprintf        _snprintf
#ifndef __CYGWIN__
typedef         unsigned long   socklen_t;
#define         MAXPATHLEN      _MAX_PATH
#define         alloca          _alloca
#endif /* Cygwin */
#endif /* ARCH */

/* to grab UINT32_MAX definitions if they exist */
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_INTTYPES_H
#include <sys/inttypes.h>
#endif

#ifdef HAVE_LRAND48
#define get_rand lrand48
#else
#define get_rand rand
#endif



#ifdef  INTSIZE64

#define 	int16	short
#define		int32	int
#ifndef UINT32_MAX
#define         UINT32_MAX      UINT_MAX
#endif
#ifndef INT32_MAX
#define         INT32_MAX       INT_MAX
#endif
#endif /* INTSIZE64 */

#ifdef  INTSIZE32

#define 	int16	short
#define		int32	int
#ifndef UINT32_MAX
#define         UINT32_MAX      UINT_MAX
#endif
#ifndef INT32_MAX
#define         INT32_MAX       INT_MAX
#endif

#endif /* INTSIZE32 */

#ifdef  INTSIZE16
#define 	int16	short
#define		int32	long
#define         UINT32_MAX      ULONG_MAX
#define         INT32_MAX       LONG_MAX
#endif

/*
 * Endian : big and little
 */

#define		ENDIAN_TYPE		0x80000080

#define		Get_endian( type )	( (type) &  ENDIAN_TYPE )
#define		Set_endian( type )	( ( (type) & ~ENDIAN_TYPE )| ARCH_ENDIAN )
#define		Same_endian( type )	( ( (type) & ENDIAN_TYPE ) == ARCH_ENDIAN )
#define		Clear_endian( type )	( (type) & ~ENDIAN_TYPE )

#define		Flip_int16( type )	( ( ((type) >> 8) & 0x00ff) | ( ((type) << 8) & 0xff00) )

#define		Flip_int32( type )	( ( ((type) >>24) & 0x000000ff) | ( ((type) >> 8) & 0x0000ff00) | ( ((type) << 8) & 0x00ff0000) | ( ((type) <<24) & 0xff000000) )

/*
 * Network definitions
 */

#define		MAX_PACKET_SIZE		1472 /*1472 = 1536-64 (of udp)*/

#define		channel			int
#define		mailbox			int

typedef	struct	dummy_membership_id {
	int32	proc_id;
	int32	time;
} membership_id;

typedef struct	dummy_group_id {
	membership_id	memb_id;
	int32		index;
} group_id;

/*
 * General Useful Types
 */

typedef         unsigned int32  int32u;
typedef         unsigned int16  int16u;
typedef         unsigned char   byte;
typedef         short           bool;
#define         TRUE            1
#define         FALSE           0

#endif	/* INC_ARCH */
