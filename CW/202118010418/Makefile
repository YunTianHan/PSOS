CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto -lmthread

all: main

main: main.o encrypt.o decrypt.o
	$(CC) -o main main.o encrypt.o decrypt.o $(LDFLAGS)

%.o: %.c common.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o main
