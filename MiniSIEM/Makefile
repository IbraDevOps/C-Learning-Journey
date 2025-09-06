CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -Wshadow -Wconversion -O2 \
       -fstack-protector-strong -D_FORTIFY_SOURCE=2
SAN=-fsanitize=address,undefined

all: mini_siem

mini_siem: mini_siem.c
	$(CC) $(CFLAGS) $(SAN) $< -o $@

clean:
	rm -f mini_siem
