#ifdef sun
#include <nss_common.h> 
#endif
#ifdef linux
#include <nss.h>
#define NSS_SUCCESS  NSS_STATUS_SUCCESS
#define NSS_NOTFOUND NSS_STATUS_NOTFOUND
#define NSS_UNAVAIL  NSS_STATUS_UNAVAIL
#define NSS_TRYAGAIN NSS_STATUS_TRYAGAIN
typedef enum nss_status nss_status_t;
#endif
  
#ifdef DEBUGMSG
#undef DEBUGMSG
#define DEBUGMSG( msg... ) openlog( "NSS_natural", LOG_CONS, LOG_AUTHPRIV ); syslog ( LOG_DEBUG, msg )
#else
#define DEBUGMSG( msg... )
#endif


#define NATURAL_OK            1
#define NATURAL_EOF          -1
#define NATURAL_RETRY        -2
#define NATURAL_ERR          -3
#define NATURAL_SOCKET_ERR   -4
#define NATURAL_CONNECT_ERR  -5
#define NATURAL_WRITE_ERR    -6
#define NATURAL_READ_ERR     -7

#define NSS_NATURAL_DEFAULT_CONFIGFILE "/etc/security/natural.conf"

#define NATURAL_PORT         55443
#define NATURAL_SERVER       "localhost"
#define NATURAL_DEFAULT_NDU  "default"

#define NATURAL_MAXBUF  20481
#define NATURAL_PWD     "x"
#define NATURAL_GRPPWD  "x"
#define NATURAL_GECOS   "natural.desktop user"
#define NATURAL_DIR     "/home"
#define NATURAL_SHELL   "/bin/bash"

nss_status_t natural_get_domain_unit (char * domain);
nss_status_t natural_auth_match (const char * domain, char *buf, size_t buflen);
nss_status_t readconfigfile(const char *cfname, char *servername, int *port);
