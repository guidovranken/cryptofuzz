all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o groestl.o groestl-cryptofuzz.o whirlpool.o
	ar rcs module.a module.o groestl.o groestl-cryptofuzz.o whirlpool.o
	ranlib module.a

groestl.o : groestl/Groestl-ref.c groestl/Groestl-ref.h
	$(CC) $(CFLAGS) -I -fPIC -c groestl/Groestl-ref.c -o groestl.o

groestl-cryptofuzz.o : groestl/groestl-cryptofuzz.c groestl/Groestl-ref.h
	$(CC) $(CFLAGS) -I -fPIC -c groestl/groestl-cryptofuzz.c -o groestl-cryptofuzz.o

whirlpool.o : whirlpool/Whirlpool.c whirlpool/nessie.h
	$(CC) $(CFLAGS) -I -fPIC -c whirlpool/Whirlpool.c -o whirlpool.o

module.o: module.cpp module.h whirlpool/nessie.h groestl/groestl-cryptofuzz.h
	$(CXX) $(CXXFLAGS) -I -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
