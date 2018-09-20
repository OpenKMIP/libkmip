##
## Makefile for libkmip
##
.POSIX:
.SUFFIXES:

SRCDIR = .
BINDIR = $(SRCDIR)/bin

MAJOR   = 0
MINOR   = 1
MICRO   = 0
VERSION = $(MAJOR).$(MINOR).$(MICRO)
SONAME  = libkmip.so.$(MAJOR)
LIBNAME = libkmip.so.$(VERSION)

CC      = cc
#CFLAGS = -std=c11 -pedantic -g3 -Og -Wall -Wextra
CFLAGS  = -std=c11 -pedantic -g3 -Wall -Wextra
LOFLAGS = -fPIC
SOFLAGS = -shared -Wl,-soname,$(SONAME) -o
LDFLAGS = -L/usr/local/lib
LDLIBS  = -lssl -lcrypto
DESTDIR = 
PREFIX  = /usr/local
KMIP    = kmip

all: demo tests

test: tests
	$(SRCDIR)/tests

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/include/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/lib/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/src/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/src
	cp demo_create $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp demo_get $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp demo_destroy $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp tests $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp -r $(SRCDIR)/docs/source/. $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/src

install_html_docs: html_docs
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/html
	cp -r $(SRCDIR)/docs/build/html/. $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/html

uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/include/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/lib/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/src/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)

uninstall_html_docs:
	rm -rf $(DESTDIR)/$(PREFIX)/share/doc/$(KMIP)/html


html_docs:
	cd docs && make html && cd ..
demo: demo_create demo_get demo_destroy
demo_get: demo_get.o kmip.o kmip_memset.o kmip_bio.o
	$(CC) $(LDFLAGS) -o demo_get demo_get.o kmip.o kmip_memset.o kmip_bio.o $(LDLIBS)
demo_create: demo_create.o kmip.o kmip_memset.o kmip_bio.o
	$(CC) $(LDFLAGS) -o demo_create demo_create.o kmip.o kmip_memset.o kmip_bio.o $(LDLIBS)
demo_destroy: demo_destroy.o kmip.o kmip_memset.o kmip_bio.o
	$(CC) $(LDFLAGS) -o demo_destroy demo_destroy.o kmip.o kmip_memset.o kmip_bio.o $(LDLIBS)
tests: tests.o kmip.o kmip_memset.o
	$(CC) $(LDFLAGS) -o tests tests.o kmip.o kmip_memset.o

demo_get.o: demo_get.c kmip_memset.h kmip.h
demo_create.o: demo_create.c kmip_memset.h kmip.h
demo_destroy.o: demo_destroy.c kmip_memset.h kmip.h
tests.o: tests.c kmip_memset.h kmip.h

kmip.o: kmip.c kmip.h kmip_memset.h
kmip.lo: kmip.c kmip.h kmip_memset.h

kmip_memset.o: kmip_memset.c kmip_memset.h
kmip_memset.lo: kmip_memset.c kmip_memset.h

kmip_bio.o: kmip_bio.c kmip_bio.h
kmip_bio.lo: kmip_bio.c kmip_bio.h

clean:
	rm -f *.o *.lo
clean_html_docs:
	cd docs && make clean && cd ..
cleanest:
	rm -f demo_create demo_get demo_destroy tests *.o *.lo
	cd docs && make clean && cd ..

.SUFFIXES: .c .o .lo .so
.c.o:
	$(CC) $(CFLAGS) -c $<
.c.lo:
	$(CC) $(CFLAGS) $(LOFLAGS) -c $<
.lo.so:
	$(CC) $(CFLAGS) $(LOFALGS) -o $<