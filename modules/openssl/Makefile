all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(OPENSSL_LIBCRYPTO_A_PATH)
	bash ../link.sh module.a $(OPENSSL_LIBCRYPTO_A_PATH)
	ranlib module.a
module.o: module.cpp module.h
	test $(OPENSSL_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
