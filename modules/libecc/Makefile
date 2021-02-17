all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL -DUSE_CRYPTOFUZZ

module.a: module.o
	test $(LIBECC_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBECC_PATH)/build/libsign.a
	ar rcs module.a module.o tmp/*
	ranlib module.a
module.o: module.cpp module.h
	test $(LIBECC_PATH)
	$(CXX) $(CXXFLAGS) -DWITH_STDLIB -I $(LIBECC_PATH)/src -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
