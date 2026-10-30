# amrun: the runtime as a Mac command, for developing it against a precompiled root.
CC = clang
CFLAGS = -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 -arch arm64 -mmacosx-version-min=14.4
SRC = runtime/main.c runtime/trap.c runtime/sys.c runtime/fs.c runtime/mm.c runtime/thread.c runtime/loader.c runtime/proc.c runtime/signal.c runtime/net.c runtime/event.c runtime/binder.c runtime/entry.S
HDR = runtime/am.h runtime/linux.h

build/amrun: $(SRC) $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SRC)
	codesign -s - -f $@

# The binder driver against fake guest processes and threads, with the sanitizers on.
build/binder_test: tests/binder_test.c runtime/binder.c runtime/fs.c $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -o $@ tests/binder_test.c runtime/binder.c runtime/fs.c

test-binder: build/binder_test
	build/binder_test

clean:
	rm -rf build/amrun build/binder_test

.PHONY: clean test-binder
