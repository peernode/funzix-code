CFLAGS += -Wall -g
LDLIBS += -lz

all: funzix

funzix: bencode/bencode.o md5/md5.o

clean:
	rm -f *.o */*.o funzix

sinclude .depend
.depend:
	$(CC) $(CPPFLAGS) -MM *.c > .depend

dist:
	rm -rf funzix-$(VER)
	svn export . funzix-$(VER)
	tar cf - funzix-$(VER) | lzma > funzix-$(VER).tar.lzma
	rm -rf funzix-$(VER)

distcheck: dist
	rm -rf funzix-$(VER)
	lzcat funzix-$(VER).tar.lzma | tar xf -
	$(MAKE) -C funzix-$(VER) check
	rm -rf funzix-$(VER)

check: all
	cd samples && ./check.sh

.PHONY: all clean
