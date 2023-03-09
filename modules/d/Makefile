all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o cryptofuzz.o
	ar rcs module.a module.o cryptofuzz.o
	ranlib module.a
cryptofuzz.o : cryptofuzz.d
	ldc2 -O3 -c cryptofuzz.d
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
