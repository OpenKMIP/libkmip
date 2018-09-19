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

SRCDIR = .
BINDIR = $(SRCDIR)/bin

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
kmip.o: kmip.c kmip.h kmip_memset.h
tests.o: tests.c kmip_memset.h kmip.h
kmip_bio.o: kmip_bio.c kmip_bio.h
kmip_memset.o: kmip_memset.c kmip_memset.h

clean:
	rm -f *.o
clean_html_docs:
	cd docs && make clean && cd ..
cleanest:
	rm -f demo_create demo_get demo_destroy tests *.o
	cd docs && make clean && cd ..

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
