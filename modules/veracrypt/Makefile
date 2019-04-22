all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o kuznyechik.o GostCipher.o Streebog.o Rmd160.o t1ha2.o Sha2.o chacha256.o Whirlpool.o Twofish.o Serpent.o Aescrypt.o Aeskey.o Aestab.o
	ar rcs module.a module.o kuznyechik.o GostCipher.o Streebog.o Rmd160.o t1ha2.o Sha2.o chacha256.o Whirlpool.o Twofish.o Serpent.o Aescrypt.o Aeskey.o Aestab.o
	ranlib module.a

module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o

kuznyechik.o : kuznyechik.c kuznyechik.h
	$(CC) $(CFLAGS) -fPIC -c kuznyechik.c -o kuznyechik.o

GostCipher.o : GostCipher.c GostCipher.h
	$(CC) $(CFLAGS) -fPIC -c GostCipher.c -o GostCipher.o

Streebog.o : Streebog.c Streebog.h
	$(CC) $(CFLAGS) -fPIC -c Streebog.c -o Streebog.o

Rmd160.o : Rmd160.c Rmd160.h
	$(CC) $(CFLAGS) -fPIC -c Rmd160.c -o Rmd160.o

t1ha2.o : t1ha2.c t1ha.h t1ha_bits.h
	$(CC) $(CFLAGS) -fPIC -c t1ha2.c -o t1ha2.o

Sha2.o : Sha2.c Sha2.h
	$(CC) $(CFLAGS) -fPIC -c Sha2.c -o Sha2.o

chacha256.o : chacha256.c chacha256.h
	$(CC) $(CFLAGS) -fPIC -c chacha256.c -o chacha256.o

Whirlpool.o : Whirlpool.c Whirlpool.h
	$(CC) $(CFLAGS) -fPIC -c Whirlpool.c -o Whirlpool.o

Twofish.o : Twofish.c Twofish.h
	$(CC) $(CFLAGS) -fPIC -c Twofish.c -o Twofish.o

Serpent.o : Serpent.c Serpent.h
	$(CC) $(CFLAGS) -fPIC -c Serpent.c -o Serpent.o

Aescrypt.o : Aescrypt.c
	$(CC) $(CFLAGS) -fPIC -c Aescrypt.c -o Aescrypt.o
Aeskey.o : Aeskey.c
	$(CC) $(CFLAGS) -fPIC -c Aeskey.c -o Aeskey.o
Aestab.o : Aestab.c
	$(CC) $(CFLAGS) -fPIC -c Aestab.c -o Aestab.o

clean:
	rm -rf *.o module.a
