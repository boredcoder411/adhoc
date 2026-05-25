CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)

ifneq ($(OPENSSL_PREFIX),)
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

LDLIBS += -lcrypto

all: main

sample: test_unsigned

main: main.c macho/constants.h signing/constants.h
	$(CC) $(CPPFLAGS) $(CFLAGS) main.c -o main $(LDFLAGS) $(LDLIBS)

test_unsigned: test.c
	$(CC) test.c -o test_unsigned -Wl,-no_adhoc_codesign

clean:
	rm -f main signature test_signed test_resigned apple_signed
