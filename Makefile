##
## Makefile for libkmip
##
.POSIX:
.SUFFIXES:

SRCDIR = .
BINDIR = $(SRCDIR)/bin

MAJOR    = 0
MINOR    = 2
MICRO    = 0
VERSION  = $(MAJOR).$(MINOR)
ARCNAME  = libkmip.a
LINKNAME = libkmip.so
SONAME   = $(LINKNAME).$(MAJOR)
LIBNAME  = $(LINKNAME).$(VERSION)
LIBS     = $(LIBNAME) $(ARCNAME)

CC      = cc
#CFLAGS = -std=c11 -pedantic -g3 -Og -Wall -Wextra
CFLAGS  = -std=c11 -pedantic -g3 -Wall -Wextra
LOFLAGS = -fPIC
SOFLAGS = -shared -Wl,-soname,$(SONAME)
LDFLAGS = -L/usr/local/lib64 -L/usr/local/lib
LDLIBS  = -lssl -lcrypto
AR      = ar csrv
DESTDIR = 
PREFIX  = /usr/local
KMIP    = kmip

OFILES  = kmip.o kmip_io.c kmip_memset.o kmip_bio.o
LOFILES = kmip.lo kmip_io.lo kmip_memset.lo kmip_bio.lo
DEMOS   = demo_create demo_get demo_destroy demo_query

all: demos tests $(LIBS)

test: tests
	$(SRCDIR)/tests

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/include/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	mkdir -p $(DESTDIR)$(PREFIX)/src/$(KMIP)
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/src
	cp demo_create $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp demo_get $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp demo_destroy $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp tests $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	cp -r $(SRCDIR)/docs/source/. $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/src
	cp $(SRCDIR)/*.c $(DESTDIR)$(PREFIX)/src/$(KMIP)
	cp $(SRCDIR)/*.h $(DESTDIR)$(PREFIX)/include/$(KMIP)
	cp $(SRCDIR)/$(LIBNAME) $(DESTDIR)$(PREFIX)/lib
	cp $(SRCDIR)/$(ARCNAME) $(DESTDIR)$(PREFIX)/lib
	cd $(DESTDIR)$(PREFIX)/lib && ln -s $(LIBNAME) $(LINKNAME) && cd -

install_html_docs: html_docs
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/html
	cp -r $(SRCDIR)/docs/build/html/. $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/html

uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/bin/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/include/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/src/$(KMIP)
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)
	rm -r $(DESTDIR)$(PREFIX)/lib/$(LINKNAME)*
	rm -r $(DESTDIR)$(PREFIX)/lib/$(ARCNAME)

uninstall_html_docs:
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/$(KMIP)/html

docs: html_docs
html_docs:
	cd $(SRCDIR)/docs && make html && cd -
demos: $(DEMOS)
demo_get: demo_get.o $(OFILES)
	$(CC) $(LDFLAGS) -o demo_get $^ $(LDLIBS)
demo_create: demo_create.o $(OFILES)
	$(CC) $(LDFLAGS) -o demo_create $^ $(LDLIBS)
demo_destroy: demo_destroy.o $(OFILES)
	$(CC) $(LDFLAGS) -o demo_destroy $^ $(LDLIBS)
demo_query: demo_query.o $(OFILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
tests: tests.o kmip.o kmip_io.o kmip_memset.o
	$(CC) $(LDFLAGS) -o tests $^

demo_get.o: demo_get.c kmip_memset.h kmip.h
demo_create.o: demo_create.c kmip_memset.h kmip.h
demo_destroy.o: demo_destroy.c kmip_memset.h kmip.h
tests.o: tests.c kmip_memset.h kmip.h
$(LIBNAME): $(LOFILES)
	$(CC) $(CFLAGS) $(SOFLAGS) -o $@ $(LOFILES)
$(ARCNAME): $(OFILES)
	$(AR) $@ $(OFILES)

kmip.o: kmip.c kmip.h kmip_memset.h
kmip.lo: kmip.c kmip.h kmip_memset.h

kmip_io.o: kmip_io.c kmip_io.h kmip.h
kmip_io.lo: kmip_io.c kmip_io.h kmip.h

kmip_memset.o: kmip_memset.c kmip_memset.h
kmip_memset.lo: kmip_memset.c kmip_memset.h

kmip_bio.o: kmip_bio.c kmip_bio.h
kmip_bio.lo: kmip_bio.c kmip_bio.h

clean:
	rm -f *.o *.lo
clean_html_docs:
	cd docs && make clean && cd ..
cleanest:
	rm -f $(DEMOS) tests *.o $(LOFILES) $(LIBS)
	cd docs && make clean && cd ..

.SUFFIXES: .c .o .lo .so
.c.o:
	$(CC) $(CFLAGS) -c $<
.c.lo:
	$(CC) $(CFLAGS) $(LOFLAGS) -c $< -o $@
#.lo.so:
#	$(CC) $(CFLAGS) $(SOFLAGS) -o $@ $?
