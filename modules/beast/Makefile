all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
module.o: module.cpp module.h
	test $(BEAST_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(BEAST_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
