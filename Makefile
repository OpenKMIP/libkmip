##
## Makefile for libkmip
##
.POSIX:
.SUFFIXES:
CC      = cc
#CFLAGS = -std=c11 -pedantic -g3 -Og -Wall -Wextra
CFLAGS  = -std=c11 -pedantic -g3 -Wall -Wextra
LDFLAGS = -L/usr/local/lib
LDLIBS  = -lssl -lcrypto
DESTDIR = 
PREFIX  = /usr/local
KMIP    = kmip

all: demo test
#all: test

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/include/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/lib/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/src/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/src
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/html
uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/include/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/lib/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/src/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)

demo: demo_create demo_get demo_destroy
demo_get: demo_get.o kmip.o kmip_memset.o kmip_bio.o
	$(CC) $(LDFLAGS) -o demo_get demo_get.o kmip.o kmip_memset.o kmip_bio.o $(LDLIBS)
demo_create: demo_create.o kmip.o kmip_memset.o kmip_bio.o
	$(CC) $(LDFLAGS) -o demo_create demo_create.o kmip.o kmip_memset.o kmip_bio.o $(LDLIBS)
demo_destroy: demo_destroy.o kmip.o kmip_memset.o kmip_bio.o
	$(CC) $(LDFLAGS) -o demo_destroy demo_destroy.o kmip.o kmip_memset.o kmip_bio.o $(LDLIBS)
test: test.o kmip.o kmip_memset.o
	$(CC) $(LDFLAGS) -o test test.o kmip.o kmip_memset.o

demo_get.o: demo_get.c kmip_memset.h kmip.h enums.h structs.h types.h
demo_create.o: demo_create.c kmip_memset.h kmip.h enums.h structs.h types.h
demo_destroy.o: demo_destroy.c kmip_memset.h kmip.h enums.h structs.h types.h
kmip.o: kmip.c kmip.h kmip_memset.h enums.h structs.h types.h
test.o: test.c kmip_memset.h kmip.h enums.h structs.h types.h
kmip_bio.o: kmip_bio.c kmip_bio.h
kmip_memset.o: kmip_memset.c kmip_memset.h

clean:
	rm -f *.o
cleanest:
	rm -f demo_get demo_create demo_destroy test *.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
