# pepenet-mesh — the shared substrate every pepenet overlay links.
#
# Produces a static lib (libpepenetnet.a) + headers under include/pepenet/.
# Hashes and the secp_* shim come from the live namespace-protocol tree (names-
# only SM); curve math is the vendored constant-time libsecp256k1 (built once
# under pepenet-social, same pin the carrier uses).
#
#   make            build lib + ./net_test
#   make check      build and run the self-test battery
#   make clean
#
# Header-collision note: the protocol repo and libsecp both ship "secp256k1.h".
# secp_shim.c includes the VENDOR one (angle); crypto.c needs protocol-sm's
# secp_* declarations (quoted) — resolved by compiling the two with different -I
# orders, then linking (same dance as namespace-indexer / carrier).

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wshadow
AR      ?= ar

# Protocol-sm primitives (SHA-256 / RIPEMD-160 / secp_* interface + shim).
# Live namespace-protocol — not social's (often lagging) submodule pin.
PROTO   := ../namespace-protocol
SMDIR   := $(PROTO)/impls/c/src
SHIMSRC := $(PROTO)/shim/secp_shim.c

# Vendored libsecp256k1 — the indexer owns the build tree the family uses
# (pepenet-social, its previous home, is retired).
IDX     := ../namespace-indexer
SECPDIR := $(IDX)/vendor/secp256k1
SECPLIB := $(IDX)/build/secp/lib/libsecp256k1.a

SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null || echo -lsqlite3)

B       := build
INC     := -Iinclude
INC_SM  := -I$(SMDIR)                            # protocol-sm's secp256k1.h (quoted)
INC_SHIM:= -I$(SECPDIR)/include -I$(SMDIR)       # vendored secp256k1.h (angle)

LIB     := libpepenetnet.a
# our own modules
OBJ     := $(B)/wire.o $(B)/view.o $(B)/crypto.o $(B)/state.o
# borrowed primitives, compiled into the same archive so consumers link one .a
PRIM    := $(B)/sha256.o $(B)/ripemd160.o $(B)/secp_shim.o

all: $(LIB) net_test state_test

$(LIB): $(OBJ) $(PRIM)
	$(AR) rcs $@ $^

net_test: $(B)/net_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(SECPLIB) $(SQLITE_LIBS)

state_test: $(B)/state_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(SECPLIB) $(SQLITE_LIBS)

$(B):
	mkdir -p $(B)

# our modules
$(B)/wire.o:   src/wire.c   | $(B); $(CC) $(CFLAGS) $(INC) -c -o $@ $<
$(B)/view.o:   src/view.c   | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/crypto.o: src/crypto.c | $(B); $(CC) $(CFLAGS) $(INC) $(INC_SM) -c -o $@ $<
$(B)/state.o:  src/state.c  | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/net_test.o: test/net_test.c | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/state_test.o: test/state_test.c | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<

# borrowed primitives
$(B)/sha256.o:    $(SMDIR)/sha256.c    | $(B); $(CC) $(CFLAGS) $(INC_SM) -c -o $@ $<
$(B)/ripemd160.o: $(SMDIR)/ripemd160.c | $(B); $(CC) $(CFLAGS) $(INC_SM) -c -o $@ $<
$(B)/secp_shim.o: $(SHIMSRC)           | $(B); $(CC) $(CFLAGS) $(INC_SHIM) -c -o $@ $<

# Vendored libsecp256k1 (the indexer's build tree; build it here if absent).
$(SECPLIB):
	cmake -S $(SECPDIR) -B $(IDX)/build/secp -DCMAKE_BUILD_TYPE=Release \
	      -DBUILD_SHARED_LIBS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF -DSECP256K1_BUILD_TESTS=OFF \
	      -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_CTIME_TESTS=OFF \
	      -DSECP256K1_BUILD_EXAMPLES=OFF -DSECP256K1_INSTALL=OFF -DSECP256K1_ENABLE_MODULE_ECDH=ON \
	      -DSECP256K1_ENABLE_MODULE_RECOVERY=OFF -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=OFF \
	      -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=OFF -DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
	      -DSECP256K1_ENABLE_MODULE_ELLSWIFT=OFF >/dev/null && cmake --build $(IDX)/build/secp -j >/dev/null

check: net_test state_test
	./net_test
	./state_test

clean:
	rm -rf $(B) $(LIB) net_test state_test

.PHONY: all check clean
