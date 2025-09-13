CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -Wpedantic -O2

all: vault vault_xor

vault: vault.c
	$(CC) $(CFLAGS) -o vault vault.c

vault_xor: vault_xor.c
	$(CC) $(CFLAGS) -o vault_xor vault_xor.c

clean:
	rm -f vault vault_xor
