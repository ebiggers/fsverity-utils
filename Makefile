CFLAGS := -O2 -Wall
EXE := fsverity

all:$(EXE)

clean:
	rm -f $(EXE)

.PHONY: all clean
