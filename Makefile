.POSIX:
.SUFFIXES:
CC     = cc
#CFLAGS = -std=c11 -pedantic -g3 -Og -Wall -Wextra
CFLAGS = -std=c11 -pedantic -g3 -Wall -Wextra
LDLIBS = -lm
PREFIX = /usr/local

all: kmip kmip_create test
kmip: kmip.o memset.o
	$(CC) $(LDFLAGS) -L/usr/local/lib -o kmip kmip.o memset.o $(LDLIBS) -lssl -lcrypto
kmip_create: kmip_create.o memset.o
	$(CC) $(LDFLAGS) -L/usr/local/lib -o kmip_create kmip_create.o memset.o $(LDLIBS) -lssl -lcrypto
test: test.o memset.o
	$(CC) $(LDFLAGS) -o test test.o memset.o $(LDLIBS)
kmip.o: kmip.c memset.h kmip.h enums.h structs.h types.h
kmip_create.o: kmip_create.c memset.h kmip.h enums.h structs.h types.h
test.o: test.c memset.h kmip.h enums.h structs.h types.h
memset.o: memset.c memset.h
clean:
	rm -f kmip.o test.o memset.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
