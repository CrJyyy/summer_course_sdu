CC ?= clang
AR ?= ar
PYTHON ?= python3
OBJDUMP ?= objdump
PKG_CONFIG ?= pkg-config
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)

CPPFLAGS := -Iinclude
CFLAGS_COMMON := -std=c11 -O3 -Wall -Wextra -Wpedantic -Werror
ifeq ($(UNAME_M),arm64)
  ARCH_FLAGS := -march=armv8.4-a+crypto
endif
CFLAGS ?= $(CFLAGS_COMMON) $(ARCH_FLAGS)

SRC := src/util.c src/aes.c src/sm4.c src/sm4_aes_assist.c src/gift64.c src/twine.c \
       src/dispatch.c src/modes.c src/arm64/aes_arm64.c \
       src/arm64/shuffle_arm64.c src/arm64/ghash_pmull.c \
       src/x86/gfni_model.c src/x86/sm4_gfni_x86.c src/x86/ghash_pclmul.c \
       src/x86/shuffle_x86.c src/x86/aes_vaes.c
SRC += src/arm64/sm4_hw_arm64.c src/x86/sm4_hw_x86.c
OBJ := $(SRC:%.c=build/%.o)
LIB := build/libsymcrypto.a
TEST := build/test_symcrypto
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3
OPENSSL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null || true)
OPENSSL_LIBS ?= $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || true)
ifeq ($(strip $(OPENSSL_LIBS)),)
  OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
  OPENSSL_LIBS := -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib -lcrypto
endif
OPENSSL_TEST := build/test_openssl_diff
X86_TEST := build/test_x86_backends
BENCH := build/bench_symcrypto
DEMO := build/sc_demo

.PHONY: all clean test test-openssl test-x86-native test-sanitize \
	test-sanitize-x86 bench bench-x86 check-x86 validate-x86 report

all: test test-sanitize check-x86 bench report

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

ifeq ($(UNAME_M),arm64)
build/src/arm64/sm4_hw_arm64.o: src/arm64/sm4_hw_arm64.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS_COMMON) -march=armv8.4-a+crypto+sm4 -c $< -o $@
endif

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

$(TEST): tests/test_symcrypto.c $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

$(OPENSSL_TEST): tests/test_openssl_diff.c $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS) $< $(LIB) \
	  $(OPENSSL_LIBS) -o $@

$(X86_TEST): tests/test_x86_backends.c $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

test: $(TEST) $(OPENSSL_TEST)
	./$(TEST)
	./$(OPENSSL_TEST)

test-openssl: $(OPENSSL_TEST)
	./$(OPENSSL_TEST)

test-x86-native: $(X86_TEST)
	./$(X86_TEST)

ifneq ($(filter MINGW% MSYS%,$(UNAME_S)),)
test-sanitize:
	./scripts/sanitize_windows.cmd generic

test-sanitize-x86:
	./scripts/sanitize_windows.cmd x86
else
test-sanitize:
	@mkdir -p build/sanitize
	$(CC) $(CPPFLAGS) -std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror \
	  $(ARCH_FLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer \
	  $(SRC) tests/test_symcrypto.c -o build/sanitize/test_symcrypto
	ASAN_OPTIONS=detect_leaks=0 ./build/sanitize/test_symcrypto

test-sanitize-x86:
	@mkdir -p build/sanitize
	$(CC) $(CPPFLAGS) -std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror \
	  -fsanitize=address,undefined -fno-omit-frame-pointer \
	  $(SRC) tests/test_x86_backends.c -o build/sanitize/test_x86_backends
	ASAN_OPTIONS=detect_leaks=0 ./build/sanitize/test_x86_backends
endif

$(BENCH): bench/bench.c $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

$(DEMO): tools/sc_demo.c $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

bench: $(BENCH)
	./$(BENCH) results/raw/native_samples.csv results/summary/native_summary.json
	./scripts/collect_sizes.sh

bench-x86: $(BENCH)
	./$(BENCH) results/raw/x86_samples.csv results/summary/x86_summary.json

check-x86:
	CC="$(CC)" AR="$(AR)" OBJDUMP="$(OBJDUMP)" ./scripts/check_x86.sh

validate-x86:
	CC="$(CC)" AR="$(AR)" OBJDUMP="$(OBJDUMP)" \
	  PKG_CONFIG="$(PKG_CONFIG)" sh ./scripts/validate_x86.sh

report:
	./scripts/build_report.sh

clean:
	rm -rf build tmp/pdfs/*
