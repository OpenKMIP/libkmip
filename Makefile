.POSIX:
.SUFFIXES:
CC     = cc
#CFLAGS = -std=c11 -pedantic -g3 -Og -Wall -Wextra
CFLAGS = -std=c11 -pedantic -g3 -Wall -Wextra
LDLIBS = -lm
PREFIX = /usr/local

all: kmip
kmip: kmip.o
	$(CC) $(LDFLAGS) -o kmip kmip.o $(LDLIBS)
kmip.o: kmip.c kmip.h enums.h
clean:
	rm -f kmip.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
