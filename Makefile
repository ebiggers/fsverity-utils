EXE := fsverity
CFLAGS := -O2 -Wall
CPPFLAGS := -D_FILE_OFFSET_BITS=64
LDLIBS := -lcrypto -lz
DESTDIR := /usr/local
SRC := $(wildcard *.c)
OBJ := $(SRC:.c=.o)
HDRS := $(wildcard *.h)

all:$(EXE)

$(EXE):$(OBJ)

$(OBJ): %.o: %.c $(HDRS)

clean:
	rm -f $(EXE) $(OBJ)

install:all
	install -Dm755 -t $(DESTDIR)/bin $(EXE) \
		mkfsverity.sh full-run-fsverity.sh

.PHONY: all clean install
