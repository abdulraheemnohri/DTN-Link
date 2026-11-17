# DTN-Link desktop shell — builds against the real libdtn_ffi engine.
#
# Prerequisite: the Rust FFI library must be built first:
#
#     cargo build -p dtn-ffi --release
#
# Targets:
#     all       build dtn-shell + dtn-ffi-selftest
#     test      build + run the FFI self test (exit != 0 on failure)
#     clean     remove binaries

UNAME_S := $(shell uname -s)
LIBDIR  := ../../target/release
ifeq ($(UNAME_S),Darwin)
  LIB := $(LIBDIR)/libdtn_ffi.dylib
else
  LIB := $(LIBDIR)/libdtn_ffi.so
endif

CFLAGS  ?= -O2 -Wall -Wextra
CPPFLAGS += -I../../crates/dtn-ffi/include -I.
LDFLAGS += -L$(abspath $(LIBDIR)) -Wl,-rpath,$(abspath $(LIBDIR))
ifeq ($(UNAME_S),Darwin)
  LDLIBS += -ldtn_ffi
else
  LDLIBS += -l:libdtn_ffi.so
endif

all: dtn-shell dtn-ffi-selftest

dtn-shell: dtn_shell.c json.c json.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ dtn_shell.c json.c $(LDFLAGS) $(LDLIBS)

dtn-ffi-selftest: dtn_ffi_selftest.c json.c json.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ dtn_ffi_selftest.c json.c $(LDFLAGS) $(LDLIBS)

test: dtn-ffi-selftest
	./dtn-ffi-selftest

clean:
	rm -f dtn-shell dtn-ffi-selftest

.PHONY: all test clean
