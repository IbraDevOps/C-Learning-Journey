CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -Wpedantic -O2

all: vault

vault: vault.c
	$(CC) $(CFLAGS) -o vault vault.c

clean:
	rm -f vault
