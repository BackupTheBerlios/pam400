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

#include <pwd.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "nss-natural.h"


nss_status_t 
internal_parse_passwd(char *buffer, size_t buflen, struct passwd *result)
{
   char *sp, *lasts;
   
   if( ( sp = strtok_r( buffer, ":", &lasts ) ) == NULL )
     return NSS_NOTFOUND;
   result->pw_name = sp;
   
   if (lasts[0] == ':' ) {
      lasts++;
      result->pw_passwd = NULL;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->pw_passwd = sp;
   }
   
   if (lasts[0] == ':' )
     return NSS_NOTFOUND;
   if( ( sp = strtok_r( NULL, ":", &lasts ) ) == NULL )
     return NSS_NOTFOUND;
   result->pw_uid = atoi( sp );
   
   if (lasts[0] == ':' )
     return NSS_NOTFOUND;
   if( ( sp = strtok_r( NULL, ":", &lasts ) ) == NULL )
     return NSS_NOTFOUND;
   result->pw_gid = atoi( sp );
   
   if (lasts[0] == ':' ) {
      lasts++;
      result->pw_gecos = NULL;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->pw_gecos = sp;
   }
   
   if (lasts[0] == ':' ) {
      lasts++;
      result->pw_dir = NULL;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->pw_dir = sp;
   }
   
   if (lasts[0] == ':' ) {
      lasts++;
      result->pw_shell = NULL;
   }else{
      sp = strtok_r( NULL, ":\n", &lasts );
      result->pw_shell = sp;
   }

   DEBUGMSG( "%s:%s:%d:%d:%s:%s:%s", result->pw_name, result->pw_passwd, result->pw_uid, result->pw_gid, result->pw_gecos, result->pw_dir, result->pw_shell );
   return NSS_SUCCESS; 
}

nss_status_t 
_nss_natural_setpwent( void )
{
   DEBUGMSG( "_nss_natural_setpwent called." );
     
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_SUCCESS );
}

nss_status_t 
_nss_natural_endpwent( void )
{
   DEBUGMSG( "_nss_natural_endpwent called." );
   
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_SUCCESS );
}

nss_status_t 
_nss_natural_getpwent_r( struct passwd *result, char *buffer, size_t buflen,
			  int *errnop )
{
   DEBUGMSG( "_nss_natural_getpwent_r called." );
   
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_NOTFOUND );
}


nss_status_t 
_nss_natural_getpwnam_r (const char *name, struct passwd *pwd,
		     char *buffer, size_t buflen)
{
   nss_status_t retval;
   char domain[256];
   int namelen;

   DEBUGMSG( "_nss_natural_getpwnam_r (%s %d)", name, buflen );

   if (name == NULL)
      return NSS_UNAVAIL;

   if (!natural_get_domain_unit (domain))
      return NSS_UNAVAIL;

   namelen = sprintf (buffer, "username:%s:%d\n", name, buflen);
   retval = natural_auth_match (domain, buffer, buflen);

   if (retval != NSS_SUCCESS)
      return retval;

   return internal_parse_passwd(buffer, buflen, pwd);
}

nss_status_t
_nss_natural_getpwuid_r (uid_t uid, struct passwd *pwd,
		     char *buffer, size_t buflen)
{
   nss_status_t retval;
   char domain[256];
   int uidlen;

   DEBUGMSG( "_nss_natural_getpwuid_r (%d %d)",uid ,buflen );

   if (!natural_get_domain_unit (domain))
      return NSS_UNAVAIL;

   uidlen = sprintf (buffer, "uid:%d:%d\n", uid, buflen);

   retval = natural_auth_match (domain, buffer, buflen);

   if (retval != NSS_SUCCESS)
      return retval;

   return internal_parse_passwd(buffer, buflen, pwd);
}
