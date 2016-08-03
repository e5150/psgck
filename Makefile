include config.mk

.SUFFIXES:
.SUFFIXES: .o .c

HDR = arg.h
SRC = psgck.c
PRG = $(SRC:.c=)
OBJ = $(SRC:.c=.o)
MAN = $(SRC:.c=.1)

all: $(PRG)

$(PRG): $(OBJ)

$(OBJ): $(SRC) $(HDR)

.c.o:
	$(CC)  $(CFLAGS) $(CPPFLAGS) -c -o $@ $< $(INCS)

.o:
	$(CC)  $(LDFLAGS) -o $@ $< $(LIBS)

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin \
	         $(DESTDIR)$(MANPREFIX)/man1
	$(INSTALL_PROGRAM) $(PRG) $(DESTDIR)$(PREFIX)/bin
	$(INSTALL_DATA) $(MAN) $(DESTDIR)$(MANPREFIX)/man1

uninstall:
	cd $(DESTDIR)$(PREFIX)/bin && rm $(PRG)
	cd $(DESTDIR)$(MANPREFIX)/man1 && rm $(MAN)

clean:
	rm -f $(OBJ) $(PRG)

.PHONY:
	all install clean uninstall
