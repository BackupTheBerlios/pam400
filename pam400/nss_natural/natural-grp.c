/* Copyright (C) 1996, 1997, 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1996.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "nss-natural.h"

/* taken from glibc source code !!! */
extern int _nss_files_parse_grent (char *buffer, struct group *grp, void *data, size_t buflen, int *errnop);

/* serious buggy */
/*
nss_status_t
internal_parse_grp(char *buffer, size_t buflen, struct group *result)
{
   char *sp, *lasts;
   int count;
   
   if( ( sp = strtok_r( buffer, ":", &lasts ) ) == NULL )
     return NSS_NOTFOUND;
   result->gr_name = sp;
   
   if (lasts[0] == ':' ) {
      result->gr_passwd = NULL;
      lasts++;
   }else{
      result->gr_passwd = strtok_r( NULL, ":", &lasts );
   }
   
   if (lasts[0] == ':' )
     return NSS_NOTFOUND;
   if( ( sp = strtok_r( NULL, ":", &lasts ) ) == NULL )
     return NSS_NOTFOUND;
   result->gr_gid = atoi( sp );
   
   result->gr_mem = (char **)sp;
   sp = strtok_r( NULL, ",", &lasts );
     
   count = 0;
   while ( sp != NULL && *sp != '\0') {
      result->gr_mem[count++] = sp;
      sp = strtok_r( NULL, ",", &lasts );
   }
   result->gr_mem[count] = NULL;

   DEBUGMSG( "%s:%s:%d: %d", result->gr_name, result->gr_passwd, result->gr_gid, count );
   return NSS_SUCCESS;
}
*/

nss_status_t
_nss_natural_setgrent( void )
{
   DEBUGMSG( "_nss_natural_setgrent called." );
   
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_SUCCESS );
}

nss_status_t
_nss_natural_endgrent_r( void )
{
   DEBUGMSG( "_nss_natural_endgrent_r called." );
   
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_SUCCESS );
}

nss_status_t
_nss_natural_getgrent_r( struct group *result, char *buffer, size_t buflen,
  int *errnop )
{
   DEBUGMSG( "_nss_natural_getgrent_r called." );
   
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_NOTFOUND );
}

nss_status_t
_nss_natural_getgrnam_r( const char *name, struct group * grp,
			    char *buffer, size_t buflen)
{
   nss_status_t retval;
   char domain[256];
   int namelen, dummy;
   
   DEBUGMSG( "_nss_natural_getgrnam_r (%s %d)",name, buflen );
   
   if (name == NULL) {
      return NSS_UNAVAIL;
   }
  
   if (natural_get_domain_unit (domain))
      return NSS_UNAVAIL;

   namelen = sprintf (buffer, "groupname:%s:%d\n", name, buflen);
   retval = natural_auth_match (domain, buffer, buflen);

   if (retval != NSS_SUCCESS)
      return retval;

   /* return internal_parse_grp(buffer, buflen, grp); */
   return _nss_files_parse_grent(buffer, grp, buffer, buflen, &dummy);
}

nss_status_t
_nss_natural_getgrgid_r( gid_t gid, struct group * grp,
			    char *buffer, size_t buflen)
{
   nss_status_t retval;
   char domain[256];
   int gidlen, dummy;

   /* DEBUGMSG( "_nss_natural_getgrgid_r (%d %d)", gid, buflen ); */

   if (!natural_get_domain_unit (domain))
      return NSS_UNAVAIL;

   gidlen = sprintf (buffer, "gid:%d:%d\n", gid, buflen);

   retval = natural_auth_match (domain, buffer, buflen);

   DEBUGMSG( "_nss_natural_getgrgid_r (%d %d retval %d)", gid, buflen, retval );
   
   if (retval != NSS_SUCCESS)
      return retval;

   /* return internal_parse_grp(buffer, buflen, grp); */
   return _nss_files_parse_grent(buffer, grp, buffer, buflen, &dummy);
}

#ifdef GLIBC_22
nss_status_t
_nss_natural_initgroups_dyn (const char *user, gid_t group, long int *start,
			 long int *size, gid_t **groupsp, long int limit,
			 int *errnop)
#else
nss_status_t
_nss_natural_initgroups (const char *user, gid_t group, long int *start,
			 long int *size, gid_t *groupsp, long int limit,
			 int *errnop)
#endif
{
   nss_status_t retval;
#ifdef GLIBC_22
   /* int i; */
   gid_t grp, *groups = *groupsp;
#else
   gid_t grp;
#endif      
   char *sp, *lasts;
   char *buffer;
   int buflen=2048;
   char domain[256];
   int cmdlen;

#ifdef GLIBC_22
   DEBUGMSG( "_nss_natural_initgroups_dyn (%s limit %ld)", user, limit);
#else
   DEBUGMSG( "_nss_natural_initgroups (%s limit %ld)", user, limit);
#endif      
   if (user == NULL || strcmp(user,"root") == 0) {
      return NSS_UNAVAIL;
   }
   
   buffer = alloca(buflen * sizeof(char));
   
   if (buffer == NULL)
     return NSS_STATUS_TRYAGAIN;
   
   if (!natural_get_domain_unit (domain))
      return NSS_UNAVAIL;

   cmdlen = sprintf (buffer, "initgroups:%s:%d\n", user, buflen);

   retval = natural_auth_match (domain, buffer, buflen);

#ifdef GLIBC_22
   DEBUGMSG( "_nss_natural_initgroups_dyn (%s retval %d [%s])", user, retval, buffer);
#else
   DEBUGMSG( "_nss_natural_initgroups (%s retval %d [%s])", user, retval, buffer);
#endif      

   if (retval != NSS_SUCCESS)
      return retval;

   if ( strlen(buffer) < 1){
    
      return NSS_UNAVAIL;
   }
     
   sp = strtok_r( buffer, ",:", &lasts );
   
   while (sp) {
#ifdef GLIBC_22
      /* reached end of buffer? */
      if (*start == *size) {
	 
	 gid_t *newgroups;
	 long int newsize;
	 
	 /* always reached kernel limit*/
	 if (limit > 0 && *size == limit) 
	   break;
	 
	 if (limit > 0)
	   newsize = 2 * *size;
	 else
	   newsize = limit > (2 * *size) ? (2 * *size) : limit;
	 
	 newgroups = realloc( *groupsp, limit * sizeof(**groupsp));
	 if (newgroups == NULL)
	   break;
	 
	 *groupsp = newgroups;
	 groups = newgroups;
	 *size = limit;
      }
#endif      
      grp = strtol(sp, (char **) NULL, 10);

      if (errno != ERANGE ) {
	 /* primary group set by caller */
	 /* DEBUGMSG( "_nss_natural_initgroups_dyn groupid[%ld] %ld", *start, grp ); */
	 if (grp != group) {
#ifdef GLIBC_22
	    groups[*start] = grp;
#else
	    groupsp[*start] = grp;
#endif      
	    *start += 1;
	    if (*start == *size)
	      break;
	 }
      }
      sp = strtok_r( NULL, ",:", &lasts );
   }

#ifdef GLIBC_22
   /* for (i=0; i < *start; i++) 
     {
	     DEBUGMSG( "_nss_natural_initgroups_dyn groupid[%d] %ld", i, groups[i] );
     } */
   
   DEBUGMSG( "_nss_natural_initgroups_dyn %s %d #%ld", user, group, *start );
#else
   DEBUGMSG( "_nss_natural_initgroups %s %ld #%ld", user, group, *start );
#endif      
   return NSS_SUCCESS;
}
