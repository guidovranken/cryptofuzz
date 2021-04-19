all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(MCL_LIBMCL_A_PATH)
	test $(MCL_LIBMCLBN384_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(MCL_LIBMCL_A_PATH)
	cd tmp && ar x $(MCL_LIBMCLBN384_A_PATH)
	ar rcs module.a module.o tmp/*
	ranlib module.a
module.o: module.cpp module.h
	test $(MCL_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(MCL_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
