all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++20 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
module.o: module.cpp module.h
	test $(INTX_PATH)
	$(CXX) $(CXXFLAGS) -I $(INTX_PATH)/include -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
