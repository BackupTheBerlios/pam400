/* 
 * pam_dce.c, v0.9, main PAM authentification function for PAM DCE
 *
 * Copyright (C) 2000 Joerg Lehmann <Joerg.Lehmann@Physik.Uni-Augsburg.DE>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software 
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _GNU_SOURCE 
#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#ifdef sun
#include <security/pam_appl.h>
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif
#ifdef linux
#include <security/pam_modules.h> 
#include <security/_pam_macros.h>
#endif
#include <syslog.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "pamio.h"
#include "nss-natural.h"


int get_access(const char *name, const char *pwd)
{
   char *buffer;
#define BUFLEN  550
   char domain[256];
   int namelen, retval=PAM_AUTH_ERR;

   if (!natural_get_domain_unit (domain))
     return retval;

   buffer = (char *) malloc(BUFLEN);
   if (buffer == NULL)
      return retval;

   openlog("PAM_natural", LOG_CONS, LOG_AUTH);

   namelen = sprintf (buffer, "password:%s:%s\n", name, pwd);
//   syslog(LOG_INFO,"server port >55443< >%s<", name);
   retval = natural_auth_match (domain, buffer, BUFLEN);

   if (retval == NATURAL_OK)
      if (!strncasecmp(buffer, "ok", 2)) 
	retval=PAM_SUCCESS;

   closelog();
   free (buffer);

   return retval;
}

PAM_EXTERN int pam_sm_authenticate(
	pam_handle_t *pamh, 
	int flags, 
	int argc, 
	const char **argv) {
	
	const char *username;
	int retval;
	char *pw;
	struct passwd *pwd;
	struct group *grp;


   openlog("PAM_natural", LOG_CONS, LOG_AUTH);
   syslog(LOG_INFO,"argc %d", argc);
   for (;argc-- > 0;argv++)
     syslog(LOG_INFO,"argv[%d] %s", argc, argv[argc]);
   closelog();
#ifdef linux
	if ( (retval=pam_get_user(pamh, &username, 0)) != PAM_SUCCESS )
#else
	if ( (retval=pam_get_user(pamh, (char **)&username, 0)) != PAM_SUCCESS )
#endif       
		return retval;	

	if ( !username || !isalnum(*username) ) 
		return PAM_USER_UNKNOWN;


	/* has password already been set? */ 

	if ( (retval=pam_get_item(pamh, PAM_AUTHTOK, (void *) &pw)) != PAM_SUCCESS ) 
		return retval;

	
	if (!pw) {	/* no, we need to prompt user for password */
		pw = _pam_read_passwd(pamh, "Password: ");
		if (!pw) return PAM_AUTH_ERR;

		if ( (retval=pam_set_item(pamh, PAM_AUTHTOK, pw)) != PAM_SUCCESS ) 
			return retval;
			
		/* Note: pam_set_item(pamh, PAM_AUTHTOK, ...) overwrites pw with zeros 
	         *	 and free()s memory. Thus, we need to get pw again */
		 
		if ( (retval=pam_get_item(pamh, PAM_AUTHTOK, (void *) &pw)) != PAM_SUCCESS ) 
			return retval;
	}

	/* printf("servername: %s\nport: %d\nusername: %s\ndfs2nfs: %d\nsys: %s\nhost: %s\ngroups: %s\nusers: %s\n\n", servername, port, username, dfs2nfs, sys, host, groups, users); */

	/* Check, if user exists */
	if ( !(pwd=getpwnam(username)) )
	   return PAM_USER_UNKNOWN;

	/* Now, we check, if the "groups" and "users" options in configfile, permit the user's login */

	if ( !(grp=getgrgid(pwd->pw_gid)) )
	   return PAM_USER_UNKNOWN;
	 

	/* TODO: Muss noch geaendert werden, wenn Markus alle Rueckgabewerte richtig liefert */

	return (get_access(username,pw)==PAM_SUCCESS) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(
	pam_handle_t *pamh, 
	int flags, int argc, 
	const char **argv) {

	return PAM_SUCCESS;
}
