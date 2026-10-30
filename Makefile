# amrun: the runtime as a Mac command, for developing it against a precompiled root.
CC = clang
CFLAGS = -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 -arch arm64 -mmacosx-version-min=14.4
SRC = runtime/main.c runtime/trap.c runtime/sys.c runtime/fs.c runtime/mm.c runtime/thread.c runtime/loader.c runtime/net.c runtime/event.c runtime/binder.c runtime/entry.S
HDR = runtime/am.h runtime/linux.h

build/amrun: $(SRC) $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SRC)
	codesign -s - -f $@

clean:
	rm -rf build/amrun

.PHONY: clean
