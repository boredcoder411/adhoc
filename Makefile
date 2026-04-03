OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)

ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lssl -lcrypto
endif

all:
	gcc main.c -o main $(OPENSSL_CFLAGS) $(OPENSSL_LIBS)

clean:
	rm -f main signature test_hello_unsigned test_hello_signed
