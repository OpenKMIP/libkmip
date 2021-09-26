##
## Makefile for libkmip
##
.POSIX:
.SUFFIXES:

SRC_DIR = src
INC_DIR = include
BIN_DIR = bin
OBJ_DIR = obj
LIB_DIR = lib
TEST_DIR = tests
DEMO_DIR = demos
DEST_DIR =
DOCS_DIR = docs
PREFIX = /usr/local
KMIP = kmip

MAJOR   = 0
MINOR   = 2
MICRO   = 1
VERSION = $(MAJOR).$(MINOR).$(MICRO)

NAME      = libkmip
CORE_NAME = $(NAME)-core

ARC_NAME       = $(NAME).a
LINK_NAME      = $(NAME).so
SO_NAME        = $(LINK_NAME).$(MAJOR)
LIB_NAME       = $(LINK_NAME).$(VERSION)

ARC_CORE_NAME  = $(CORE_NAME).a
LINK_CORE_NAME = $(CORE_NAME).so
SO_CORE_NAME   = $(LINK_CORE_NAME).$(MAJOR)
LIB_CORE_NAME  = $(LINK_CORE_NAME).$(VERSION)

LIBS           = $(LIB_DIR)/$(LIB_NAME) $(LIB_DIR)/$(LIB_CORE_NAME) $(LIB_DIR)/$(ARC_NAME) $(LIB_DIR)/$(ARC_CORE_NAME)

CC = cc
AR = ar csrv
CFLAGS  = -std=c11 -pedantic -g3 -Wall -Wextra
LOFLAGS = -fPIC
SOFLAGS = -shared -Wl,-soname,$(SO_NAME)
SOCOREFLAGS = -shared -Wl,-soname,$(SO_CORE_NAME)
LDFLAGS = -L/usr/local/lib64 -L/usr/local/lib
LDLIBS  = -lssl -lcrypto 

INC_FLAGS = -I$(INC_DIR)

H_FILES = $(INC_DIR)/*.h
SRC_C_FILES = $(SRC_DIR)/*.c
DEMO_C_FILES = $(DEMO_DIR)/*.c
TEST_C_FILES = $(TEST_DIR)/*.c

SRC_O_CORE_FILES = $(OBJ_DIR)/kmip.o
SRC_O_CORE_FILES += $(OBJ_DIR)/kmip_memset.o

SRC_O_FILES = $(SRC_O_CORE_FILES)
SRC_O_FILES += $(OBJ_DIR)/kmip_io.o
SRC_O_FILES += $(OBJ_DIR)/kmip_bio.o

SRC_LO_FILES = $(SRC_O_FILES:.o=.lo)
SRC_LO_CORE_FILES = $(SRC_O_CORE_FILES:.o=.lo)

DEMO_O_FILES = $(OBJ_DIR)/demo_get.o
DEMO_O_FILES += $(OBJ_DIR)/demo_create.o
DEMO_O_FILES += $(OBJ_DIR)/demo_destroy.o
DEMO_O_FILES += $(OBJ_DIR)/demo_query.o

TEST_O_FILES = $(OBJ_DIR)/tests.o

## Build targets
all: objs demos tests libs

objs: $(OBJ_DIR) \
      $(SRC_O_FILES) \
      $(SRC_LO_FILES)

demos: objs \
       $(BIN_DIR) \
       $(DEMO_O_FILES) \
       $(BIN_DIR)/demo_get \
       $(BIN_DIR)/demo_create \
       $(BIN_DIR)/demo_destroy \
       $(BIN_DIR)/demo_query

tests: objs \
       $(TEST_O_FILES) \
       $(BIN_DIR)/tests

libs: objs \
      $(LIB_DIR) \
      $(LIBS)

$(BIN_DIR)/demo_get: $(OBJ_DIR)/demo_get.o $(SRC_O_FILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(BIN_DIR)/demo_create: $(OBJ_DIR)/demo_create.o $(SRC_O_FILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(BIN_DIR)/demo_destroy: $(OBJ_DIR)/demo_destroy.o $(SRC_O_FILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(BIN_DIR)/demo_query: $(OBJ_DIR)/demo_query.o $(SRC_O_FILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/tests: $(TEST_O_FILES) $(OBJ_DIR)/kmip.o $(OBJ_DIR)/kmip_io.o $(OBJ_DIR)/kmip_memset.o
	$(CC) $(LDFLAGS) -o $@ $^

### .o build rules
$(OBJ_DIR)/kmip.o: $(SRC_DIR)/kmip.c $(INC_DIR)/kmip.h $(INC_DIR)/kmip_memset.h
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@
$(OBJ_DIR)/kmip_io.o: $(SRC_DIR)/kmip_io.c $(INC_DIR)/kmip_io.h $(INC_DIR)/kmip.h
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@
$(OBJ_DIR)/kmip_memset.o: $(SRC_DIR)/kmip_memset.c $(INC_DIR)/kmip_memset.h
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@
$(OBJ_DIR)/kmip_bio.o: $(SRC_DIR)/kmip_bio.c $(INC_DIR)/kmip_bio.h
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

$(OBJ_DIR)/demo_get.o: $(DEMO_DIR)/demo_get.c $(H_FILES)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@
$(OBJ_DIR)/demo_create.o: $(DEMO_DIR)/demo_create.c $(H_FILES)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@
$(OBJ_DIR)/demo_destroy.o: $(DEMO_DIR)/demo_destroy.c $(H_FILES)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@
$(OBJ_DIR)/demo_query.o: $(DEMO_DIR)/demo_query.c $(H_FILES)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

$(OBJ_DIR)/tests.o: $(TEST_DIR)/tests.c $(INC_DIR)/kmip.h $(INC_DIR)/kmip_io.h $(INC_DIR)/kmip_memset.h
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

### .lo build rules
$(OBJ_DIR)/kmip.lo: $(SRC_DIR)/kmip.c $(INC_DIR)/kmip.h $(INC_DIR)/kmip_memset.h
	$(CC) $(CFLAGS) $(INC_FLAGS) $(LOFLAGS) -c $< -o $@
$(OBJ_DIR)/kmip_io.lo: $(SRC_DIR)/kmip_io.c $(INC_DIR)/kmip_io.h $(INC_DIR)/kmip.h
	$(CC) $(CFLAGS) $(INC_FLAGS) $(LOFLAGS) -c $< -o $@
$(OBJ_DIR)/kmip_memset.lo: $(SRC_DIR)/kmip_memset.c $(INC_DIR)/kmip_memset.h
	$(CC) $(CFLAGS) $(INC_FLAGS) $(LOFLAGS) -c $< -o $@
$(OBJ_DIR)/kmip_bio.lo: $(SRC_DIR)/kmip_bio.c $(INC_DIR)/kmip_bio.h
	$(CC) $(CFLAGS) $(INC_FLAGS) $(LOFLAGS) -c $< -o $@

### library build rules
$(LIB_DIR)/$(LIB_NAME): $(SRC_LO_FILES)
	$(CC) $(CFLAGS) $(SOFLAGS) -o $@ $(SRC_LO_FILES) $(LDLIBS)
$(LIB_DIR)/$(LIB_CORE_NAME): $(SRC_LO_CORE_FILES)
	$(CC) $(CFLAGS) $(SOCOREFLAGS) -o $@ $(SRC_LO_CORE_FILES)
$(LIB_DIR)/$(ARC_NAME): $(SRC_O_FILES)
	$(AR) $@ $(SRC_O_FILES)
$(LIB_DIR)/$(ARC_CORE_NAME): $(SRC_O_CORE_FILES)
	$(AR) $@ $(SRC_O_CORE_FILES)

## Target to run test suite
test: tests
	$(BIN_DIR)/tests

## Dynamic directory creation rules
$(BIN_DIR):
	mkdir -p $@
$(OBJ_DIR):
	mkdir -p $@
$(LIB_DIR):
	mkdir -p $@

## Install targets
install: all
	mkdir -p $(DEST_DIR)$(PREFIX)/bin/$(KMIP)
	mkdir -p $(DEST_DIR)$(PREFIX)/include/$(KMIP)
	mkdir -p $(DEST_DIR)$(PREFIX)/lib
	mkdir -p $(DEST_DIR)$(PREFIX)/src/$(KMIP)
	mkdir -p $(DEST_DIR)$(PREFIX)/share/doc/$(KMIP)/src
	cp $(BIN_DIR)/demo_create $(DEST_DIR)$(PREFIX)/bin/$(KMIP)
	cp $(BIN_DIR)/demo_get $(DEST_DIR)$(PREFIX)/bin/$(KMIP)
	cp $(BIN_DIR)/demo_destroy $(DEST_DIR)$(PREFIX)/bin/$(KMIP)
	cp $(BIN_DIR)/demo_query $(DEST_DIR)$(PREFIX)/bin/$(KMIP)
	cp -r $(DOCS_DIR)/source/. $(DEST_DIR)$(PREFIX)/share/doc/$(KMIP)/src
	cp $(SRC_DIR)/*.c $(DEST_DIR)$(PREFIX)/src/$(KMIP)
	cp $(INC_DIR)/*.h $(DEST_DIR)$(PREFIX)/include/$(KMIP)
	cp $(LIB_DIR)/* $(DEST_DIR)$(PREFIX)/lib
	cd $(DEST_DIR)$(PREFIX)/lib && ln -s $(LIB_NAME) $(LINK_NAME) && cd -
	cd $(DEST_DIR)$(PREFIX)/lib && ln -s $(LIB_NAME) $(SO_NAME) && cd -
	cd $(DEST_DIR)$(PREFIX)/lib && ln -s $(LIB_CORE_NAME) $(LINK_CORE_NAME) && cd -
	cd $(DEST_DIR)$(PREFIX)/lib && ln -s $(LIB_CORE_NAME) $(SO_CORE_NAME) && cd -

install_html_docs: html_docs
	mkdir -p $(DEST_DIR)$(PREFIX)/share/doc/$(KMIP)/html
	cp -r $(DOCS_DIR)/build/html/. $(DEST_DIR)$(PREFIX)/share/doc/$(KMIP)/html

uninstall:
	rm -rf $(DEST_DIR)$(PREFIX)/bin/$(KMIP)
	rm -rf $(DEST_DIR)$(PREFIX)/include/$(KMIP)
	rm -rf $(DEST_DIR)$(PREFIX)/src/$(KMIP)
	rm -rf $(DEST_DIR)$(PREFIX)/share/doc/$(KMIP)
	rm -r $(DEST_DIR)$(PREFIX)/lib/$(LINK_NAME)*
	rm -r $(DEST_DIR)$(PREFIX)/lib/$(LINK_CORE_NAME)*
	rm -r $(DEST_DIR)$(PREFIX)/lib/$(ARC_NAME)
	rm -r $(DEST_DIR)$(PREFIX)/lib/$(ARC_CORE_NAME)

uninstall_html_docs:
	rm -rf $(DEST_DIR)$(PREFIX)/share/doc/$(KMIP)/html

docs: html_docs
html_docs:
	cd $(DOCS_DIR) && make html && cd -

## Clean up rules
clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR) $(LIB_DIR)
clean_html_docs:
	cd $(DOCS_DIR) && make clean && cd ..
cleanest: clean clean_html_docs
