ifdef WITH_GEOIP
GEOC=-DWITH_GEOIP
GEOLD=-lGeoIP
endif

ifdef WITH_DNSBLENV
DNSBLM= dnsblenv
endif

ifdef WITH_UCSPI2SOCKET
UCSPI2SOCKM= ucspi2socket
endif

CFLAGS=-I/usr/local/include -I/opt/local/include -O2 -Wall ${GEOC} 
LDFLAGS=-L/usr/local/lib -L/opt/local/lib -lsqlite3 -lpthread ${GEOLD}

ifdef WITH_CARES14
CFLAGS+= -DCARES14
endif

ifdef DEBUG
CFLAGS+= -DDEBUG
endif

# pthread is added to be sure (possibly required by sqlite itself)
PREFIX?=/usr/local

.PHONY: all clean install install-man

all: greylite ${DNSBLM} ${UCSPI2SOCKM}

dnsblenv: dnsblenv.c logmsg.o
	cc ${CFLAGS} -o $@ $? ${LDFLAGS} -lcares

greylite: logmsg.o greylite.c

ucspi2socket: logmsg.c logmsg.h ucspi2socket.c

logmsg.o: logmsg.c logmsg.h

cidr2firstlast:

clean:
	rm -f greylite cidr2firstlast logmsg.o dnsblenv ucspi2socket

install: greylite ${DNSBLM} ${UCSPI2SOCKM} install-man
	install -d $(PREFIX)/bin
	install -s greylite ${DNSBLM} ${UCSPI2SOCKM} $(PREFIX)/bin/

install-man:
	install -d $(PREFIX)/man/man8/
	gzip --stdout greylite.8 > $(PREFIX)/man/man8/greylite.8.gz
