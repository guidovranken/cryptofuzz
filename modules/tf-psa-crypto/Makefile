# PSA Crypto API based on the Mbed TLS implementation

all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(MBEDTLS_LIBMBEDCRYPTO_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(MBEDTLS_LIBMBEDCRYPTO_A_PATH)
	ar rcs module.a module.o tmp/*
	ranlib module.a
module.o: module.cpp module.h
	test $(MBEDTLS_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(MBEDTLS_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
