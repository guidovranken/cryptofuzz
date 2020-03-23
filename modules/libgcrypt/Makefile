all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o bn_ops.o
	test $(LIBGCRYPT_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBGCRYPT_A_PATH)
	ar rcs module.a module.o bn_ops.o tmp/*
	ranlib module.a
bn_ops.o : bn_ops.cpp bn_ops.h
	$(CXX) $(CXXFLAGS) -I $(LIBGCRYPT_INCLUDE_PATH) -fPIC -c bn_ops.cpp -o bn_ops.o
module.o: module.cpp module.h
	test $(LIBGCRYPT_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -DLIBGCRYPT_ENABLE_NAMESPACE_WEAK -I $(LIBGCRYPT_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
