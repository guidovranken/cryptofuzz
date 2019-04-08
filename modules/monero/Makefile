all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o jh.o groestl.o skein.o hmac-keccak.o memwipe.o keccak.o
	ar rcs module.a module.o jh.o groestl.o skein.o hmac-keccak.o memwipe.o keccak.o
	ranlib module.a
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
jh.o : jh.c jh.h
	$(CC) $(CFLAGS) -fPIC -c jh.c -o jh.o 
groestl.o : groestl.c groestl.h
	$(CC) $(CFLAGS) -fPIC -c groestl.c -o groestl.o 
skein.o : skein.c skein.h
	$(CC) $(CFLAGS) -fPIC -c skein.c -o skein.o
hmac-keccak.o : hmac-keccak.c hmac-keccak.h
	$(CC) $(CFLAGS) -fPIC -c hmac-keccak.c -o hmac-keccak.o
memwipe.o : memwipe.c memwipe.h
	$(CC) $(CFLAGS) -fPIC -c memwipe.c -o memwipe.o
keccak.o : keccak.c keccak.h
	$(CC) $(CFLAGS) -fPIC -c keccak.c -o keccak.o
clean:
	rm -rf *.o module.a
