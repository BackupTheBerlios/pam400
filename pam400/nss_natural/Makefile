CC = gcc
#CFLAGS = -g -D_REENTRANT -DDEBUGMSG -O2 -Wall -Wstrict-prototypes
CFLAGS = -DGLIBC_22 -D_REENTRANT -DDEBUGMSG -O2 -Wall -Wstrict-prototypes
#LFLAGS = -g -S -O2 -shared -L/usr/lib/debug
LFLAGS = -O2 -shared
#LIBS = -lpamd
LIBS = -lpam

OBJS = natural-pwd.o natural-spwd.o natural-grp.o auth-service.o config.o

all: libnss_natural.so.2 pam_natural.so

libnss_natural.so.2: $(OBJS)
	ld $(LFLAGS) -o libnss_natural.so.2 $(OBJS)

client: client.o auth-service.o
	$(CC) $(CFLAGS) -o $@ $^

pam_natural.so: pamnatural.o pamio.o auth-service.o config.o
	ld $(LFLAGS) -o $@ $^ $(LIBS)

pamnatural.o:  pamnatural.c pamio.h
	$(CC) -c  -fPIC $(CFLAGS) pamnatural.c

pamio.o:  pamio.c pamio.h
	$(CC) -c  -fPIC $(CFLAGS) pamio.c

natural-pwd.o : natural-pwd.c nss-natural.h auth-service.c
natural-spwd.o: natural-spwd.c nss-natural.h auth-service.c
natural-grp.o : natural-grp.c nss-natural.h auth-service.c
auth-service.o: auth-service.c nss-natural.h config.c
client.o      : client.c nss-natural.h auth-service.c 
config.o      : config.c

.c.o:
	$(CC) -c $(CFLAGS) $*.c

install: libnss_dce.so.2
	strip libnss_dce.so.2
	install -m 755 $< /lib

clean:
	rm -f $(OBJS) pamio.o pamnatural.o libnss_natural.so.2 pam_natural.so
