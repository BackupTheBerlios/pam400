#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "nss-natural.h"

void _remove_l_t_whitechars (char **s) {
   int i;  
   /* delete leading whitechars */
   while (**s!=0 && isspace(**s)) (*s)++;
   
   /* delete trailing whitechars */
   i=strlen(*s)-1;
   while (i>=0 && isspace((*s)[i])) i--;
   (*s)[i+1]=0;
}

nss_status_t readconfigfile(const char *cfname, char *servername, int *port)
{
   FILE *cf;
   char line[NATURAL_MAXBUF+2];
   int lnr=0;
   
   strcpy (servername, NATURAL_SERVER);
   *port = NATURAL_PORT;
   
   if (!cfname)
     cfname=NSS_NATURAL_DEFAULT_CONFIGFILE;
   
   if ((cf = fopen(cfname,"r")) ) {
      
      openlog("natural", 0, LOG_AUTH);
            
      while ( !feof(cf)) {
	 char *dummy, *arg, *pos, *param;
	 
	 *line = '\0';
	 fgets(line, NATURAL_MAXBUF, cf);
	 lnr++;
	 
	 if ((dummy=strchr(line,'#')))
	   *dummy = '\0';

	 dummy=line;
	 _remove_l_t_whitechars(&dummy);
	 
	 if (strlen(dummy)==0)
	   continue;
	 
	 
	 if ( !(pos=strchr(dummy,'=')) ) {
	    syslog(LOG_ERR, "Syntax error in natural configfile (line #%d): no '=' found.\n", lnr);
	    continue;
	 }
								            
	 /* separate line in "param=arg" */
	 param=dummy;
	 arg=pos+1;
	 *pos='\0';
	 
	 _remove_l_t_whitechars(&param);
	 _remove_l_t_whitechars(&arg);
	 
	 /* printf("param: '%s'\t arg: '%s'\n", param,arg);  */
	 
	 if ( !strcasecmp(param, "server") ) {
	    if ( strlen(arg)==0  ) {
	      syslog(LOG_ERR, "Syntax error in natural configfile (line #%d): No servername specified. Using %s\n", lnr, NATURAL_SERVER);
	    }else {
	       strncpy(servername, arg, 255);
	       servername[255]='\0';
	    }
	 }else if ( !strcasecmp(param, "port") ) {
	    char *eptr;
	    int newport;
	    newport=(int) strtol(arg, &eptr, 10);
	    if ( strlen(arg)==0 || strlen(eptr)>0 ) {
	      syslog(LOG_ERR, "Syntax error in natural configfile (line #%d): Port number invalid. Using %d\n", lnr, NATURAL_PORT);
	    }else 
	      *port=newport;
	 }else{
	   syslog(LOG_ERR, "Syntax error in natural configfile (line #%d): Invalid option '%s'.\n", lnr, param);
	 }
      }
      fclose(cf);
   }else{
      syslog(LOG_NOTICE, "natural configfile missing. Using server %s Port %d\n", NATURAL_SERVER, NATURAL_PORT);
   }
   closelog();
   return 1;
}

