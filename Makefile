CC ?= cc
EMCC ?= emcc
WEB_DIR ?= web
CFLAGS ?= -std=c11 -Wall -Wextra -O2
WASM_CFLAGS ?= -std=c11 -Wall -Wextra -O3 -DADHOC_SIGNER_WASM
WASM_LDFLAGS ?= \
	-sMODULARIZE=1 \
	-sEXPORT_ES6=1 \
	-sENVIRONMENT=web,worker \
	-sFILESYSTEM=0 \
	-sALLOW_MEMORY_GROWTH=1 \
	--no-entry \
	-sEXPORTED_FUNCTIONS='["_malloc","_free","_sign_macho_wasm"]'
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)

ifneq ($(OPENSSL_PREFIX),)
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

LDLIBS += -lcrypto

all: build_dir main

build_dir:
	mkdir -p build

main: main.c macho/constants.h signing/constants.h
	$(CC) $(CPPFLAGS) $(CFLAGS) main.c -o build/main $(LDFLAGS) $(LDLIBS)

wasm: build_dir main.c macho/constants.h signing/constants.h
	$(EMCC) $(WASM_CFLAGS) main.c -o build/adhoc_signer.emcc.js $(WASM_LDFLAGS)
	cp build/adhoc_signer.emcc.wasm $(WEB_DIR)/adhoc_signer.wasm

test: build_dir main test.c
	$(CC) test.c -o build/test
	codesign --remove-signature build/test
	./build/main build/test "com.example.test" build/test_signed
	codesign -dvvv build/test_signed

clean:
	rm -rf build

.PHONY: all clean main wasm build_dir
