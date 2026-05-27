CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)

ifneq ($(OPENSSL_PREFIX),)
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

LDLIBS += -lcrypto

all: build_dir main

build_dir:
	mkdir build

main: main.c macho/constants.h signing/constants.h
	$(CC) $(CPPFLAGS) $(CFLAGS) main.c -o build/main $(LDFLAGS) $(LDLIBS)

test: build_dir main test.c
	$(CC) test.c -o build/test
	codesign --remove-signature build/test
	./build/main build/test "com.example.test" build/test_signed
	codesign -dvvv build/test_signed

clean:
	rm -rf build

.PHONY: all clean main build_dir
