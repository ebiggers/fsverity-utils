CFLAGS := -O2 -Wall
EXE := fsverityset fsveritymeasure

all:$(EXE)

clean:
	rm -f $(EXE)

.PHONY: all clean
