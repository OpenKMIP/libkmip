.POSIX:
.SUFFIXES:
CC     = cc
#CFLAGS = -std=c11 -pedantic -g3 -Og -Wall -Wextra
CFLAGS = -std=c11 -pedantic -g3 -Wall -Wextra
LDLIBS = -lm
PREFIX = /usr/local

all: kmip test
kmip: kmip.o
	$(CC) $(LDFLAGS) -L/usr/local/lib -o kmip kmip.o $(LDLIBS) -lssl -lcrypto
test: test.o
	$(CC) $(LDFLAGS) -o test test.o $(LDLIBS)
kmip.o: kmip.c kmip.h enums.h
test.o: test.c kmip.h enums.h
clean:
	rm -f kmip.o test.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
