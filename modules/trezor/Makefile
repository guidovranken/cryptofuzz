all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o address.o base58.o bignum.o blake256.o blake2b.o ecdsa.o groestl.o hasher.o hmac_drbg.o memzero.o nist256p1.o rand.o rfc6979.o ripemd160.o secp256k1.o sha2.o sha3.o hmac.o pbkdf2.o
	rm -rf module.a
	ar rcs module.a module.o address.o base58.o bignum.o blake256.o blake2b.o ecdsa.o groestl.o hasher.o hmac_drbg.o memzero.o nist256p1.o rand.o rfc6979.o ripemd160.o secp256k1.o sha2.o sha3.o hmac.o pbkdf2.o
	ranlib module.a

address.o : $(TREZOR_FIRMWARE_PATH)/crypto/address.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/address.c -o address.o

base58.o : $(TREZOR_FIRMWARE_PATH)/crypto/base58.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/base58.c -o base58.o

bignum.o : $(TREZOR_FIRMWARE_PATH)/crypto/bignum.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/bignum.c -o bignum.o

blake256.o : $(TREZOR_FIRMWARE_PATH)/crypto/blake256.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/blake256.c -o blake256.o

blake2b.o : $(TREZOR_FIRMWARE_PATH)/crypto/blake2b.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/blake2b.c -o blake2b.o

ecdsa.o : $(TREZOR_FIRMWARE_PATH)/crypto/ecdsa.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/ecdsa.c -o ecdsa.o

groestl.o : $(TREZOR_FIRMWARE_PATH)/crypto/groestl.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/groestl.c -o groestl.o

hasher.o : $(TREZOR_FIRMWARE_PATH)/crypto/hasher.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/hasher.c -o hasher.o

hmac_drbg.o : $(TREZOR_FIRMWARE_PATH)/crypto/hmac_drbg.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/hmac_drbg.c -o hmac_drbg.o

memzero.o : $(TREZOR_FIRMWARE_PATH)/crypto/memzero.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/memzero.c -o memzero.o

nist256p1.o : $(TREZOR_FIRMWARE_PATH)/crypto/nist256p1.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/nist256p1.c -o nist256p1.o

rand.o : $(TREZOR_FIRMWARE_PATH)/crypto/rand.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/rand.c -o rand.o

rfc6979.o : $(TREZOR_FIRMWARE_PATH)/crypto/rfc6979.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/rfc6979.c -o rfc6979.o

ripemd160.o : $(TREZOR_FIRMWARE_PATH)/crypto/ripemd160.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/ripemd160.c -o ripemd160.o

secp256k1.o : $(TREZOR_FIRMWARE_PATH)/crypto/secp256k1.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/secp256k1.c -o secp256k1.o

sha2.o : $(TREZOR_FIRMWARE_PATH)/crypto/sha2.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/sha2.c -o sha2.o

sha3.o : $(TREZOR_FIRMWARE_PATH)/crypto/sha3.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/sha3.c -o sha3.o

hmac.o : $(TREZOR_FIRMWARE_PATH)/crypto/hmac.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/hmac.c -o hmac.o

pbkdf2.o : $(TREZOR_FIRMWARE_PATH)/crypto/pbkdf2.c
	$(CC) $(CFLAGS) -c -DUSE_RFC6979 -DRAND_PLATFORM_INDEPENDENT -I $(TREZOR_FIRMWARE_PATH)/crypto/ $(TREZOR_FIRMWARE_PATH)/crypto/pbkdf2.c -o pbkdf2.o

module.o: module.cpp module.h
	test $(TREZOR_FIRMWARE_PATH)
	$(CXX) $(CXXFLAGS) -I $(TREZOR_FIRMWARE_PATH)/crypto -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
