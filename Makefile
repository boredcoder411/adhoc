all:
	gcc main.c -o main -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

clean:
	rm -f main signature
