SRC = $(wildcard mdns/*.c)
OBJ = $(SRC:.c=.o)

CFLAGS=-std=gnu99 -Wall

ifdef DEBUG
CFLAGS+= -g
else
CFLAGS+= -Os
endif

MDNS_REPEATER_VERSION=$(shell git rev-parse HEAD )

CFLAGS+= -DMDNS_REPEATER_VERSION="\"$(MDNS_REPEATER_VERSION)\""

.PHONY: all
all: mdns-repeater

mdns-repeater: $(OBJ) mdns-repeater.o
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ -I. $<

.PHONY: clean
clean:
	-rm -f $(OBJ)
	-rm -f mdns-repeater.o
	-rm -f mdns-repeater
