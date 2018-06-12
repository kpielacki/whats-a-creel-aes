CC=gcc

all:
	mkdir bin
	$(CC) *.h enc.c -o ./bin/enc
	$(CC) *.h dec.c -o ./bin/dec

clean:
	rm -r ./bin
