all:
	gcc main.c debug.c -o main -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

clean:
	rm -f main signature
