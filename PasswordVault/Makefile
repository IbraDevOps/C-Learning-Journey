CC=gcc
CFLAGS?=-std=gnu99 -Wall -Wextra -Wpedantic -O2
LDLIBS_CRYPTO=-lcrypto

all: vault vault_xor vault_aes

vault: vault.c
	$(CC) $(CFLAGS) -o vault vault.c

vault_xor: vault_xor.c
	$(CC) $(CFLAGS) -o vault_xor vault_xor.c

vault_aes: vault_aes.c crypto.c crypto.h
	$(CC) $(CFLAGS) -o vault_aes vault_aes.c crypto.c $(LDLIBS_CRYPTO)

clean:
	rm -f vault vault_xor vault_aes
