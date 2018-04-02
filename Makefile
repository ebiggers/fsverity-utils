CFLAGS := -O2 -Wall
EXE := fsverity
DESTDIR := /usr/local

all:$(EXE)

clean:
	rm -f $(EXE)

install:all
	install -Dm755 -t $(DESTDIR)/bin $(EXE) fsveritysetup \
		mkfsverity.sh full-run-fsverity.sh

.PHONY: all clean
