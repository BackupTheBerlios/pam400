/* 
 * pamio.c, v0.9, input/output helper routines for PAM DCE
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
#include <stdlib.h>
#ifdef sun
#include <security/pam_appl.h>
#include <security/pam_modules.h> 
#endif
#ifdef linux
#include <security/pam_modules.h> 
#include <security/_pam_macros.h>
#endif
#include "pamio.h"

/* _pam_output_string:
 *   gibt output via conversation-Funktion aus */

int _pam_output_string(pam_handle_t *pamh, const char *output) {

	const void *item;
	int retval;

	void *appdata_ptr = NULL;
   
	/* conversation function */
	int (*conv) (int num_msg, 
        	     const struct pam_message **msg, 
	     	struct pam_response **resp,
	     	void *appdata_ptr);

	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;


	/* get conversation function */

	if ( (retval=pam_get_item(pamh,PAM_CONV, &item)) != PAM_SUCCESS ) 
	  	return retval;
	conv = ((const struct pam_conv *) item)->conv;

	msg[0].msg_style=PAM_TEXT_INFO;
	msg[0].msg= (char *)output;
	pmsg[0]=&msg[0];

	/* important: it is not guaranteed that application sets resp! */
	resp=NULL;		

	/* output via conversation function  */

	if ( (retval=conv(1, 
	                  (const struct pam_message **) pmsg, 
			  &resp, 
			  appdata_ptr)) != PAM_SUCCESS )
		return retval;


	/* practical, undocumented (?) feature: */
	/* Ueberschreibt Inhalt von resp und gibt Speicherplatz frei */

	if (resp) _pam_drop_reply(resp,1); 
	
	return PAM_SUCCESS;

}

/* _pam_read_passwd:
 *   ask user for password, using prompt and return pointer to 
 *   password string
 * Notice:
 *   this function allocates memory for password string
 *   which should be free()´ed by calling function */

char *_pam_read_passwd(pam_handle_t *pamh, const char *prompt) {

	const void *item;
	int retval; 		/* not really needed here */
	char *p;


	void *appdata_ptr = NULL;
   
	/* conversation function */
	int (*conv) (int num_msg, 
        	     const struct pam_message **msg, 
	     	struct pam_response **resp,
	     	void *appdata_ptr);

	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;

	/* get conversation function */

	if ( (retval=pam_get_item(pamh,PAM_CONV, &item)) != PAM_SUCCESS ) 
	  	return NULL;
	conv = ((const struct pam_conv *) item)->conv;

	msg[0].msg_style=PAM_PROMPT_ECHO_OFF;
	msg[0].msg = (char *)prompt;
	pmsg[0]=&msg[0];

	/* important: it is not guaranteed that application sets resp! */
	resp=NULL;		

	/* output via conversation function  */

	if ( (retval=conv(1, 
	                  (const struct pam_message **) pmsg, 
			  &resp, 
			  appdata_ptr)) != PAM_SUCCESS )
		return NULL;

	/* if possible, return password */

	if (resp) {
	  p=strdup(resp->resp);
	  _pam_drop_reply(resp,1); 
	  return p;
	}
	
	return NULL;

}
