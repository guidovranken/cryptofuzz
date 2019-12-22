all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o bn_ops.o
	test $(LIBCRYPTOPP_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBCRYPTOPP_A_PATH)
	ar rcs module.a module.o bn_ops.o tmp/*
	ranlib module.a
bn_ops.o : bn_ops.cpp bn_ops.h
	$(CXX) $(CXXFLAGS) -DCRYPTOPP_ENABLE_NAMESPACE_WEAK -I $(CRYPTOPP_INCLUDE_PATH) -fPIC -c bn_ops.cpp -o bn_ops.o
module.o: module.cpp module.h bn_ops.h
	test $(CRYPTOPP_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -DCRYPTOPP_ENABLE_NAMESPACE_WEAK -I $(CRYPTOPP_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
