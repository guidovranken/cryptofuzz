all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(LIBHASHTREE_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBHASHTREE_A_PATH)
	ar rcs module.a module.o tmp/*
	ranlib module.a
module.o: module.cpp module.h
	test $(LIBHASHTREE_A_PATH)
	$(CXX) $(CXXFLAGS) -I -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
