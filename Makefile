CC = gcc
CFLAGS = -g -Wall -I include/
LDFLAGS = -lcrypto

main: src/aes.c
		$(CC) $(CFLAGS) src/aes.c -o aes256 $(LDFLAGS)

clean:
		$(RM) aes256


