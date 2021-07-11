all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o secp256k1_api.o
	test $(LIBSECP256K1_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBSECP256K1_A_PATH)
	ar rcs module.a module.o secp256k1_api.o tmp/*
	ranlib module.a
secp256k1_api.o : secp256k1_api.c secp256k1_api.h
	$(CC) $(CFLAGS) -I $(SECP256K1_INCLUDE_PATH) -I $(SECP256K1_INCLUDE_PATH)/include -fPIC -c secp256k1_api.c -o secp256k1_api.o
module.o: module.cpp module.h secp256k1_api.h
	test $(SECP256K1_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(SECP256K1_INCLUDE_PATH)/include -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
