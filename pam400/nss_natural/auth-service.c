#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "nss-natural.h"


void 
init_sockaddr (struct sockaddr_in *name,
	       const char *hostname,
	       uint16_t port)
{
   struct hostent *hostinfo;
   
   name->sin_family = AF_INET;
   name->sin_port = htons (port);
   hostinfo = gethostbyname (hostname);
   if (hostinfo == NULL) {
      name->sin_addr.s_addr = htonl (INADDR_ANY);
   }else{
      name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
   }
}

int connection_init (void)
{
   char server[512];
   int port;
   int sock;
   struct sockaddr_in servername;
   
   readconfigfile(NULL, server, &port);
   /* Create the socket. */
   sock = socket (PF_INET, SOCK_STREAM, 0);
   if (sock < 0)
      return NATURAL_SOCKET_ERR;

   /* Connect to the server. */
   init_sockaddr (&servername, server, port);
   if (0 > connect (sock, 
		   (struct sockaddr *) &servername,
                   sizeof (servername)))
     return NATURAL_CONNECT_ERR;
   
   return sock;
}

int ask_service(int filedes, char *buffer, int bufferlen)
{
   int nbytes;
   
   nbytes = write (filedes, buffer, strlen (buffer) + 1);
   if (nbytes < 0) 
     return NATURAL_WRITE_ERR;
   
   memset(buffer, 0, bufferlen);
     
   nbytes = read (filedes, buffer, bufferlen);
   if (nbytes < 0)
      /* Read error. */
      return NATURAL_READ_ERR;

   
   if (nbytes == 0)
       /* End-of-file. */
       return NATURAL_EOF;

   /* delete trailing newline */
   if ( '\n' == buffer[nbytes-1] )
       nbytes--;
   
   /* Data read. */
   if ( nbytes >= bufferlen ) {
      buffer[bufferlen-1] = '\0';
   }else{
      buffer[nbytes] = '\0';
   }
   
   return NSS_SUCCESS;

}

nss_status_t natural_get_domain_unit (char * domain)
{
   char *ndu = NATURAL_DEFAULT_NDU;
   size_t len;
   
   len = strlen(ndu);
   strncpy(domain, ndu, len);
   domain[len] = '\0';
   
   return NSS_SUCCESS;
}

nss_status_t natural_auth_match (const char * domain, char *buf, size_t buflen)
{
   int retval = NSS_TRYAGAIN; 
   int sock;
   
   sock = connection_init();
   if (sock > -1) {

      if (ask_service(sock, buf, buflen) == NSS_SUCCESS)
	 retval = NSS_SUCCESS;

      close(sock);
   }
   
   if (retval != NSS_SUCCESS)
      memset(buf, 0, buflen);
     
   return retval;
}
