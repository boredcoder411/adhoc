CC ?= cc
EMCC ?= emcc
WEB_DIR ?= web
WASM_OPENSSL_PREFIX ?= $(CURDIR)/build/wasm-openssl
WASM_OPENSSL_VERSION ?= 3.5.9
WASM_OPENSSL_ARCHIVE = build/openssl-$(WASM_OPENSSL_VERSION).tar.gz
WASM_OPENSSL_SOURCE = build/openssl-$(WASM_OPENSSL_VERSION)
WASM_OPENSSL_SHA256 = 603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
CFLAGS ?= -std=c11 -Wall -Wextra -O2
WASM_CPPFLAGS ?=
WASM_CFLAGS ?= -std=c11 -Wall -Wextra -O3 -DADHOC_SIGNER_WASM
WASM_LDFLAGS ?= \
	-sMODULARIZE=1 \
	-sEXPORT_ES6=1 \
	-sENVIRONMENT=web,worker \
	-sFILESYSTEM=0 \
	-sALLOW_MEMORY_GROWTH=1 \
	-sEXPORTED_RUNTIME_METHODS='["HEAPU8","HEAPU32"]' \
	--no-entry \
	-sEXPORTED_FUNCTIONS='["_malloc","_free","_sign_macho_wasm_adhoc","_sign_macho_wasm_cert"]'
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)

ifneq ($(OPENSSL_PREFIX),)
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

LDLIBS += -lcrypto

all: build_dir main

build_dir:
	mkdir -p build

main: build_dir main.c signing/identity.c signing/identity.h macho/constants.h signing/constants.h
	$(CC) $(CPPFLAGS) $(CFLAGS) main.c signing/identity.c -o build/main $(LDFLAGS) $(LDLIBS)

$(WASM_OPENSSL_ARCHIVE):
	mkdir -p build
	curl -fL "https://www.openssl.org/source/openssl-$(WASM_OPENSSL_VERSION).tar.gz" -o "$@.tmp"
	echo "$(WASM_OPENSSL_SHA256)  $@.tmp" | shasum -a 256 -c -
	mv "$@.tmp" "$@"

$(WASM_OPENSSL_SOURCE)/.unpacked: $(WASM_OPENSSL_ARCHIVE)
	tar -xzf "$<" -C build
	touch "$@"

$(WASM_OPENSSL_PREFIX)/lib/libcrypto.a: $(WASM_OPENSSL_SOURCE)/.unpacked
	cd "$(WASM_OPENSSL_SOURCE)" && CROSS_COMPILE= CC=$(EMCC) AR=emar RANLIB=emranlib ./Configure \
		linux-generic32 no-asm no-shared \
		no-threads no-dso no-engine no-tests --prefix="$(WASM_OPENSSL_PREFIX)"
	$(MAKE) -C "$(WASM_OPENSSL_SOURCE)" CC=$(EMCC) AR=emar RANLIB=emranlib build_libs
	$(MAKE) -C "$(WASM_OPENSSL_SOURCE)" CC=$(EMCC) AR=emar RANLIB=emranlib install_dev

wasm-openssl: $(WASM_OPENSSL_PREFIX)/lib/libcrypto.a

wasm: build_dir wasm-openssl main.c signing/identity.c signing/identity.h macho/constants.h signing/constants.h
	mkdir -p $(WEB_DIR)
	$(EMCC) $(WASM_CPPFLAGS) $(WASM_CFLAGS) -I$(WASM_OPENSSL_PREFIX)/include main.c signing/identity.c \
		-L$(WASM_OPENSSL_PREFIX)/lib -lcrypto -o $(WEB_DIR)/adhoc_signer.js $(WASM_LDFLAGS)

test: build_dir main test.c
	$(CC) test.c -o build/test
	codesign --remove-signature build/test
	./build/main build/test "com.example.test" build/test_adhoc
	codesign --verify --strict --verbose=2 ./build/test_adhoc
	./build/main build/test com.example.hello ./build/test_cert --p12 test.p12 --p12-pass test
	codesign --verify --strict --verbose=2 ./build/test_cert

clean:
	rm -rf build

.PHONY: all clean main wasm wasm-openssl build_dir
