.POSIX:
.SUFFIXES:
CC     = cc
#CFLAGS = -std=c11 -pedantic -g3 -Og -Wall -Wextra
CFLAGS = -std=c11 -pedantic -g3 -Wall -Wextra
LDLIBS = -lm
PREFIX = /usr/local

all: demo_get demo_create demo_destroy test
demo_get: demo_get.o kmip.o memset.o
	$(CC) $(LDFLAGS) -L/usr/local/lib -o demo_get demo_get.o kmip.o memset.o $(LDLIBS) -lssl -lcrypto
demo_create: demo_create.o kmip.o memset.o
	$(CC) $(LDFLAGS) -L/usr/local/lib -o demo_create demo_create.o kmip.o memset.o $(LDLIBS) -lssl -lcrypto
demo_destroy: demo_destroy.o kmip.o memset.o
	$(CC) $(LDFLAGS) -L/usr/local/lib -o demo_destroy demo_destroy.o kmip.o memset.o $(LDLIBS) -lssl -lcrypto
test: test.o kmip.o memset.o
	$(CC) $(LDFLAGS) -o test test.o kmip.o memset.o $(LDLIBS)
demo_get.o: demo_get.c memset.h kmip.h enums.h structs.h types.h
demo_create.o: demo_create.c memset.h kmip.h enums.h structs.h types.h
demo_destroy.o: demo_destroy.c memset.h kmip.h enums.h structs.h types.h
kmip.o: kmip.c kmip.h memset.h enums.h structs.h types.h
test.o: test.c memset.h kmip.h enums.h structs.h types.h
memset.o: memset.c memset.h
clean:
	rm -f demo_get demo_create demo_destroy test *.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
