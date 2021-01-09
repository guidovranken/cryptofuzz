all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL -DCRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES

module.a: module.o bn_ops.o bn_helper.o ecdsa_generic.o ecdsa_448.o ecdsa_25519.o
	test $(WOLFCRYPT_LIBWOLFSSL_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(WOLFCRYPT_LIBWOLFSSL_A_PATH)
	ar rcs module.a module.o bn_ops.o bn_helper.o ecdsa_generic.o ecdsa_448.o ecdsa_25519.o tmp/*
	ranlib module.a
bn_ops.o : bn_ops.cpp bn_ops.h bn_helper.h
	$(CXX) $(CXXFLAGS) -I $(WOLFCRYPT_INCLUDE_PATH) -fPIC -c bn_ops.cpp -o bn_ops.o
bn_helper.o : bn_helper.cpp bn_helper.h
	$(CXX) $(CXXFLAGS) -I $(WOLFCRYPT_INCLUDE_PATH) -fPIC -c bn_helper.cpp -o bn_helper.o
ecdsa_generic.o : ecdsa_generic.cpp ecdsa_generic.h custom_curves.h
	$(CXX) $(CXXFLAGS) -I $(WOLFCRYPT_INCLUDE_PATH) -fPIC -c ecdsa_generic.cpp -o ecdsa_generic.o
ecdsa_448.o : ecdsa_448.cpp ecdsa_448.h
	$(CXX) $(CXXFLAGS) -I $(WOLFCRYPT_INCLUDE_PATH) -fPIC -c ecdsa_448.cpp -o ecdsa_448.o
ecdsa_25519.o : ecdsa_25519.cpp ecdsa_25519.h
	$(CXX) $(CXXFLAGS) -I $(WOLFCRYPT_INCLUDE_PATH) -fPIC -c ecdsa_25519.cpp -o ecdsa_25519.o
module.o: module.cpp module.h
	test $(WOLFCRYPT_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(WOLFCRYPT_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
