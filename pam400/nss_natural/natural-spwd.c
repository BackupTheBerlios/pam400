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

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include "nss-natural.h"


nss_status_t
internal_parse_shadow(char *buffer, size_t buflen, struct spwd *result)
{
   char *sp, *lasts;
     
   if( ( sp = strtok_r( buffer, ":", &lasts ) ) == NULL )
     return NSS_NOTFOUND;
   result->sp_namp = sp;
   
   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_pwdp = NULL;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_pwdp = sp;
   }
   
   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_lstchg = 10000;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_lstchg = atol( sp );
   }
   
   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_min = 0;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_min = atol( sp );
   }

   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_max = 99999;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_max = atol( sp );
   }

   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_warn = 7;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_warn = atol( sp );
   }

   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_inact = -1;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_inact = atol( sp );
   }

   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_expire = -1;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_expire = atol( sp );
   }

   if (lasts[0] == ':' ) {
      lasts++;
      result->sp_flag = -1;
   }else{
      sp = strtok_r( NULL, ":", &lasts );
      result->sp_flag = atol( sp );
   }

   DEBUGMSG( "%s:%s:%ld:%ld:%ld:%ld:%ld:%ld:%ld", result->sp_namp, result->sp_pwdp, result->sp_lstchg, result->sp_min, result->sp_max, result->sp_warn, result->sp_inact, result->sp_expire, result->sp_flag );
   return NSS_SUCCESS; 
}

nss_status_t
_nss_natural_setspent( void )
{
   DEBUGMSG( "_nss_natural_setspent called." );
     
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_SUCCESS );
}

nss_status_t
_nss_natural_endspent( void )
{
   DEBUGMSG( "_nss_natural_endspent called." );
   
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_SUCCESS );
}

nss_status_t
_nss_natural_getspent_r( struct spwd *result, char *buffer, size_t buflen,
			  int *errnop )
{
   DEBUGMSG( "_nss_natural_getspent_r called." );
   
   /*
    * We currently do not allow sequential lookups ...
    */
   return( NSS_NOTFOUND );
}

nss_status_t
_nss_natural_getspnam_r (const char *name, struct spwd *sp,
		     char *buffer, size_t buflen)
{
   nss_status_t retval;
   char domain[256];
   int namelen;

   if (name == NULL)
      return NSS_UNAVAIL;

   DEBUGMSG( "_nss_natural_getspnam_r (%s %d)", name, buflen );
   if (!natural_get_domain_unit (domain))
      return NSS_UNAVAIL;

   namelen = sprintf (buffer, "shadowname:%s:%d\n", name, buflen);
   retval = natural_auth_match (domain, buffer, buflen);

  if (retval != NSS_SUCCESS)
     return retval;

  return internal_parse_shadow(buffer, buflen, sp);
}
