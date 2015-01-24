CFLAGS ?= -g -fsanitize=address
CFLAGS += -Wall -Wextra -W
CPPFLAGS += -DBE_DEBUG=3

all: test

test: bencode.o

clean:
	rm -f *.o core test

.PHONY: all clean
