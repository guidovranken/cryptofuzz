ifeq ($(OS),Windows_NT)
  UNAME ?= Windows
else
  UNAME := $(shell uname -s)
endif

VERSION=.0
SOSUFFIX = .so
SOVERSION=$(SOSUFFIX)$(VERSION)
LIBPREFIX = lib
YASM64FLAGS = -DLINUX
LDEXTRALIBS = -lm -lc

ifeq ($(UNAME),Darwin)
# OS X
PREFIX       ?= /usr/local
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := macho32
OBJ64FORMAT  := macho64
INLINE_AS := 1


SOSUFFIX = .dylib
SOVERSION=$(VERSION)$(SOSUFFIX)
SODIR=$(LIBDIR)
LDFLAGS=-lc++ -dynamiclib -install-name=$(LIBDIR)/libcppcrypto$(SOVERSION)
endif

ifeq ($(UNAME),Linux)
# Linux
PREFIX       ?= /usr
ifeq ($(shell getconf LONG_BIT), 64)
ifneq ($(wildcard $(PREFIX)/lib64/.),)
LIBDIR       ?= $(PREFIX)/lib64
else
LIBDIR       ?= $(PREFIX)/lib
endif
else
LIBDIR       ?= $(PREFIX)/lib
endif
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
INLINE_AS := 1
SODIR=$(LIBDIR)
LDFLAGS=-Wl,-z,now -Wl,-z,relro -Wl,-soname,libcppcrypto$(SOVERSION)


endif

ifeq ($(UNAME),FreeBSD)
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
SODIR=$(LIBDIR)
LDFLAGS=-lc++


endif

ifeq ($(UNAME),SunOS)
# Solaris
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
SODIR=$(LIBDIR)


MAKE_DIR=ginstall -d
INSTALL_DATA=ginstall
endif

ifeq ($(UNAME),Windows)
define \n


endef
$(error Windows build is supported only via Visual C++ project files,$(\n)or run 'make UNAME=Cygwin' to build for Cygwin)
endif

ifeq ($(UNAME),Cygwin)
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
SODIR        ?= /bin
OBJ32FORMAT  := win32
OBJ64FORMAT  := win64
LDEXTRALIBS=-lm -lc -lssp
SOSUFFIX = .dll
SOVERSION=$(VERSION)$(SOSUFFIX)


LIBPREFIX = cyg
YASM64FLAGS = -DWINABI -DWIN_ABI -DWIN64
LDFLAGS=-Wl,--out-implib=libcppcrypto.dll.a -Wl,--export-all-symbols -Wl,--enable-auto-import 
endif

ifndef OBJ64FORMAT
$(error Unsupported platform $(UNAME), please edit the makefile)
endif

INCLUDEDIR   ?= $(PREFIX)/include/cppcrypto
MAKE_DIR     ?= install -d
INSTALL_DATA ?= install




ifeq ($(shell getconf LONG_BIT), 64)
PLATFORM64BIT=1
else
PLATFORM64BIT=0
endif

ifeq ($(UNAME),SunOS)


ifeq ($(shell isainfo -v 2>&1 | grep -q "64-bit" && echo 64bit || echo 32bit), 64bit)
PLATFORM64BIT=1
CFLAGS += -m64
EXTRA_CFLAGS += m64
CXXFLAGS += -m64
LDFLAGS += -m64
endif
ARCHSSSE3=-xarch=ssse3
ARCHSSE41=-xarch=sse4_1
ARCHAES=-xarch=aes
ARCHAVX2=-xarch=avx2
else
ARCHSSSE3=-mssse3
ARCHSSE41=-msse4.1
ARCHAES=-msse4.1 -maes
ARCHAVX2=-maes -mavx2
endif

cc-name = $(shell $(CC) -v 2>&1 | grep -q "clang version" && echo clang || echo gcc)
ifeq ($(cc-name),clang)
NOASFLAGS=-no-integrated-as
endif

OBJS= blake.o groestl.o cpuinfo.o sha256.o sha512.o skein256.o skein512.o skein1024.o whirlpool.o crypto_hash.o \
      blake256-sse2.o blake256-sse41.o blake512-sse2.o blake512-sse41.o groestl-impl-ssse3.o groestl-impl-aesni.o \
      kupyna.o rijndael.o cbc.o hmac.o rijndael-impl-aesni.o rijndael-impl-aesni-avx2.o pbkdf2.o anubis.o ctr.o \
      block_cipher.o twofish.o sha3.o sha3_impl_ssse3.o KeccakF-1600-opt64.o KeccakSponge.o jh.o sha1.o \
      jh-impl-sse.o streebog.o gost3411-2012-sse41.o sm3.o md5.o serpent.o cast6.o camellia.o kalyna.o \
      aria.o kuznyechik.o sm4.o mars.o blake2.o blake2b.o blake2s.o threefish.o scrypt.o crypto_scrypt_smix_sse2.o \
      argon2.o thread_pool.o salsa20.o salsa20-xmm6int.o hc.o chacha.o chacha-xmm.o poly1305.o poly1305-impl-sse2.o \
      simon.o speck.o KeccakP-1600-AVX2.o KeccakSpongeWidth1600.o KeccakHash.o sha3_impl_avx2.o

OBJS32 = skein512mmx.o sha512-nayuki.o whirlpool-nayuki.o sha1-nayuki.o serpent-waite.o poly1305-32.o
OBJS64 = b256avxs.o sha256_sse4.o sha512_sse4.o sha256_avx2_rorx2.o sha512_avx2_rorx.o \
         sha1_ssse3.o gost3411-2012-sse2.o poly1305-64.o

ifdef INLINE_AS
OBJS32 += sha256-cryptopp-x86-linux.o 
OBJS64 += sha256-cryptopp-x64-linux.o 
CXXFLAGS += -DINLINE_AS
endif

ifeq ($(PLATFORM64BIT), 1)
   CFLAGS += -fPIC -D_M_X64
   EXTRA_CFLAGS += -fPIC -D_M_X64
   CXXFLAGS += -fPIC -D_M_X64
   OBJS += $(OBJS64)
else
   OBJS += $(OBJS32)
endif

all: $(LIBPREFIX)cppcrypto$(SOVERSION)

$(LIBPREFIX)cppcrypto$(SOVERSION): $(OBJS) 
	$(CXX) $(LDFLAGS) -shared -o $(LIBPREFIX)cppcrypto$(SOVERSION)  $(OBJS) $(LDEXTRALIBS)
	ar rcs libcppcrypto.a  $(OBJS)


clean:
	rm -f *.o 3rdparty/*.o libcppcrypto.* $(LIBPREFIX)cppcrypto.*

install: $(LIBPREFIX)cppcrypto$(SOVERSION)
	$(MAKE_DIR) $(DESTDIR) $(DESTDIR)$(PREFIX) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) -pm 0755 $(LIBPREFIX)cppcrypto$(SOVERSION) $(DESTDIR)$(SODIR)
	cd $(DESTDIR)$(SODIR) && ln -s -f $(LIBPREFIX)cppcrypto$(SOVERSION) $(DESTDIR)$(SODIR)/$(LIBPREFIX)cppcrypto$(SOSUFFIX)
	$(INSTALL_DATA) -pm 0644 *.h  $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) -pm 0644 libcppcrypto*.a $(DESTDIR)$(LIBDIR)

blake256-sse2.o: 3rdparty/blake256-sse2.c
	$(CC) -c $(CFLAGS) 3rdparty/blake256-sse2.c

blake256-sse41.o: 3rdparty/blake256-sse41.c
	$(CC) -c $(CFLAGS) $(ARCHSSE41) 3rdparty/blake256-sse41.c

blake512-sse2.o: 3rdparty/blake512-sse2.c
	$(CC) -c $(CFLAGS) 3rdparty/blake512-sse2.c

blake512-sse41.o: 3rdparty/blake512-sse41.c
	$(CC) -c $(CFLAGS) $(ARCHSSE41) 3rdparty/blake512-sse41.c

blake2b.o: 3rdparty/blake2b.c
	$(CC) -c $(CFLAGS) $(ARCHSSE41) 3rdparty/blake2b.c

blake2s.o: 3rdparty/blake2s.c
	$(CC) -c $(CFLAGS) $(ARCHSSE41) 3rdparty/blake2s.c

b256avxs.o: 3rdparty/b256avxs.asm
	yasm -f $(OBJ64FORMAT) $(YASM64FLAGS) -o b256avxs.o 3rdparty/b256avxs.asm

sha256_sse4.o: 3rdparty/sha256_sse4.asm
	yasm -f $(OBJ64FORMAT) $(YASM64FLAGS) -o sha256_sse4.o 3rdparty/sha256_sse4.asm

sha256_avx2_rorx2.o: 3rdparty/sha256_avx2_rorx2.asm
	yasm -f $(OBJ64FORMAT) $(YASM64FLAGS) -o sha256_avx2_rorx2.o 3rdparty/sha256_avx2_rorx2.asm

sha512_sse4.o: 3rdparty/sha512_sse4.asm
	yasm -f $(OBJ64FORMAT) $(YASM64FLAGS) -o sha512_sse4.o 3rdparty/sha512_sse4.asm

sha512_avx2_rorx.o: 3rdparty/sha512_avx2_rorx.asm
	yasm -f $(OBJ64FORMAT) $(YASM64FLAGS) -o sha512_avx2_rorx.o 3rdparty/sha512_avx2_rorx.asm

sha256-cryptopp-x64-linux.o: 3rdparty/sha256-cryptopp-x64-linux.cpp
	g++ $(EXTRA_CFLAGS) -c 3rdparty/sha256-cryptopp-x64-linux.cpp

groestl-impl-ssse3.o: 3rdparty/groestl-impl-ssse3.cpp
	$(CXX) -c $(CXXFLAGS) $(ARCHSSSE3) 3rdparty/groestl-impl-ssse3.cpp

groestl-impl-aesni.o: 3rdparty/groestl-impl-aesni.cpp
	$(CXX) -c $(CXXFLAGS) $(ARCHAES) 3rdparty/groestl-impl-aesni.cpp

rijndael-impl-aesni.o: rijndael-impl-aesni.cpp
	$(CXX) -c $(CXXFLAGS) $(ARCHAES) rijndael-impl-aesni.cpp

rijndael-impl-aesni-avx2.o: rijndael-impl-aesni-avx2.cpp
	$(CXX) -c $(CXXFLAGS) $(ARCHAVX2) rijndael-impl-aesni-avx2.cpp

skein512mmx.o: 3rdparty/skein512mmx.cpp
	$(CXX) -c $(CXXFLAGS) 3rdparty/skein512mmx.cpp

sha512-nayuki.o: 3rdparty/sha512-nayuki.asm
	yasm -f $(OBJ32FORMAT) -r raw -p gas -o sha512-nayuki.o 3rdparty/sha512-nayuki.asm

whirlpool-nayuki.o: 3rdparty/whirlpool-nayuki.asm
	yasm -f $(OBJ32FORMAT) -r raw -p gas -o whirlpool-nayuki.o 3rdparty/whirlpool-nayuki.asm

sha256-cryptopp-x86-linux.o: 3rdparty/sha256-cryptopp-x86-linux.cpp
	$(CXX) -c $(CXXFLAGS) $(NOASFLAGS) 3rdparty/sha256-cryptopp-x86-linux.cpp

sha3_impl_ssse3.o: 3rdparty/sha3_impl_ssse3.cpp
	$(CXX) -c $(CXXFLAGS) $(ARCHSSSE3) 3rdparty/sha3_impl_ssse3.cpp

KeccakSponge.o: 3rdparty/KeccakSponge.c
	$(CC) -c $(CFLAGS) $(ARCHSSSE3) 3rdparty/KeccakSponge.c

KeccakF-1600-opt64.o: 3rdparty/KeccakF-1600-opt64.c
	$(CC) -c $(CFLAGS) $(ARCHSSSE3) 3rdparty/KeccakF-1600-opt64.c

KeccakP-1600-AVX2.o: 3rdparty/KeccakP-1600-AVX2.cpp
	$(CXX) -c $(CFLAGS) $(ARCHAVX2) 3rdparty/KeccakP-1600-AVX2.cpp

KeccakSpongeWidth1600.o: 3rdparty/KeccakSpongeWidth1600.c
	$(CC) -c $(CFLAGS) $(ARCHAVX2) 3rdparty/KeccakSpongeWidth1600.c

KeccakHash.o: 3rdparty/KeccakHash.c
	$(CC) -c $(CFLAGS) $(ARCHAVX2) 3rdparty/KeccakHash.c

sha3_impl_avx2.o: 3rdparty/sha3_impl_avx2.cpp
	$(CXX) -c $(CXXFLAGS) $(ARCHAVX2) 3rdparty/sha3_impl_avx2.cpp

sha1-nayuki.o: 3rdparty/sha1-nayuki.asm
	yasm -f $(OBJ32FORMAT) -r raw -p gas -o sha1-nayuki.o 3rdparty/sha1-nayuki.asm

sha1_ssse3.o: 3rdparty/sha1_ssse3.asm
	yasm -f $(OBJ64FORMAT) $(YASM64FLAGS) -o sha1_ssse3.o 3rdparty/sha1_ssse3.asm

jh-impl-sse.o: 3rdparty/jh-impl-sse.cpp
	$(CXX) -c $(CXXFLAGS) 3rdparty/jh-impl-sse.cpp

gost3411-2012-sse2.o: 3rdparty/gost3411-2012-sse2.c
	$(CC) -c $(CFLAGS) 3rdparty/gost3411-2012-sse2.c

gost3411-2012-sse41.o: 3rdparty/gost3411-2012-sse41.c
	$(CC) -c $(CFLAGS) $(ARCHSSE41) 3rdparty/gost3411-2012-sse41.c

serpent-waite.o: 3rdparty/serpent-waite.asm
	yasm -f $(OBJ32FORMAT) -o serpent-waite.o 3rdparty/serpent-waite.asm

crypto_scrypt_smix_sse2.o: 3rdparty/crypto_scrypt_smix_sse2.c
	$(CC) -c $(CFLAGS) 3rdparty/crypto_scrypt_smix_sse2.c

salsa20-xmm6int.o: 3rdparty/salsa20-xmm6int.c
	$(CC) -c $(CFLAGS) 3rdparty/salsa20-xmm6int.c

chacha-xmm.o: 3rdparty/chacha-xmm.c
	$(CC) -c $(CFLAGS) $(ARCHSSSE3) 3rdparty/chacha-xmm.c

poly1305-32.o: 3rdparty/poly1305-32.asm
	yasm -f $(OBJ32FORMAT) -r nasm -p gas -o poly1305-32.o 3rdparty/poly1305-32.asm

poly1305-64.o: 3rdparty/poly1305-64.asm
	yasm -f $(OBJ64FORMAT) $(YASM64FLAGS) -r nasm -p gas -o poly1305-64.o 3rdparty/poly1305-64.asm

poly1305-impl-sse2.o: 3rdparty/poly1305-impl-sse2.cpp
	$(CXX) -c $(CXXFLAGS) 3rdparty/poly1305-impl-sse2.cpp

