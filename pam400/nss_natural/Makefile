CC = gcc
#CFLAGS = -g -D_REENTRANT -DDEBUGMSG -O2 -Wall -Wstrict-prototypes
CFLAGS = -DGLIBC_22 -D_REENTRANT -DDEBUGMSG -O2 -Wall -Wstrict-prototypes -fPIC
#LFLAGS = -O2 -shared -L/usr/lib/debug
LFLAGS = -O2 -shared
#LIBS = -lpamd
LIBS = -lpam
EXTLIBS = -L. -lnss_natural-2.2

OBJS1 = natural-pwd.o natural-spwd.o natural-grp.o auth-service.o
OBJS2 = pamnatural.o pamio.o

all: libnss_natural-2.2.so pam_natural.so

libnss_natural-2.2.so: $(OBJS1)
	ld $(LFLAGS) -o $@ $(OBJS1) $(LIBS)
	ln -sf $@ libnss_natural.so
	
pam_natural.so: $(OBJS2)
	ld $(LFLAGS) -o $@ $(OBJS2) $(LIBS) $(EXTLIBS)

pamnatural.o:  pamnatural.c pamio.h
	$(CC) -c  -fPIC $(CFLAGS) pamnatural.c

pamio.o:  pamio.c pamio.h
	$(CC) -c  -fPIC $(CFLAGS) pamio.c


.c.o:
	$(CC) -c $(CFLAGS) $*.c

install: all
	cp libnss_natural-2.2.so /lib
	cp pam_natural.so /lib/security
	echo "ncclient	  55443/tcp" >> /etc/services
	ln -sf /lib/libnss_natural-2.2.so /lib/libnss_natural.so
	ln -sf /lib/libnss_natural-2.2.so /lib/libnss_natural.so.2
	ldconfig

clean:
	rm -f $(OBJS1) $(OBJS2) pamio.o pamnatural.o libnss_natural-2.2.so libnss_natural.so pam_natural.so

natural-pwd.o : natural-pwd.c nss-natural.h auth-service.c
natural-spwd.o: natural-spwd.c nss-natural.h auth-service.c
natural-grp.o : natural-grp.c nss-natural.h auth-service.c
auth-service.o: auth-service.c nss-natural.h
