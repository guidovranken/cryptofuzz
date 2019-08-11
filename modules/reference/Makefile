all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o xxhash.o groestl.o groestl-cryptofuzz.o whirlpool.o argon2/libargon2.a
	mkdir tmpargon2 && cd tmpargon2 && ar x ../argon2/libargon2.a
	ar rcs module.a module.o xxhash.o groestl.o groestl-cryptofuzz.o whirlpool.o tmpargon2/*.o $(if $(CRYPTOFUZZ_REFERENCE_CITY_O_PATH),$(CRYPTOFUZZ_REFERENCE_CITY_O_PATH),$())
	rm -rf tmpargon2/
	ranlib module.a

xxhash.o : xxhash/xxhash.c xxhash/xxhash.h
	$(CC) $(CFLAGS) -I -fPIC -c xxhash/xxhash.c -o xxhash.o

groestl.o : groestl/Groestl-ref.c groestl/Groestl-ref.h
	$(CC) $(CFLAGS) -I -fPIC -c groestl/Groestl-ref.c -o groestl.o

groestl-cryptofuzz.o : groestl/groestl-cryptofuzz.c groestl/Groestl-ref.h
	$(CC) $(CFLAGS) -I -fPIC -c groestl/groestl-cryptofuzz.c -o groestl-cryptofuzz.o

whirlpool.o : whirlpool/Whirlpool.c whirlpool/nessie.h
	$(CC) $(CFLAGS) -I -fPIC -c whirlpool/Whirlpool.c -o whirlpool.o

argon2/libargon2.a :
	cd argon2 && make

module.o: module.cpp module.h whirlpool/nessie.h groestl/groestl-cryptofuzz.h
	$(CXX) $(CXXFLAGS) -I -fPIC -c module.cpp $(if $(CRYPTOFUZZ_REFERENCE_CITY_O_PATH),"-DCRYPTOFUZZ_REFERENCE_CITY_O_PATH=\"$(CRYPTOFUZZ_REFERENCE_CITY_O_PATH)\"","") -o module.o
clean:
	rm -rf *.o module.a
