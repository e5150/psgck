PREFIX = /usr/local
MANPREFIX = $(PREFIX)/man

CFLAGS   = -g -O3 -fPIC -ansi -Wall -Wextra -Werror -pedantic -Wno-parentheses
CPPFLAGS = -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE
LDFLAGS  =
INCS     = -I.
LIBS     =

CC = cc
INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA    = $(INSTALL) -m644
