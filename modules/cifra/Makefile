all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf module.a
	ar rcs module.a module.o $(CIFRA_PATH)/*.o
	ranlib module.a
module.o: module.cpp module.h
	test $(CIFRA_PATH)
	$(CXX) $(CXXFLAGS) -I $(CIFRA_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
