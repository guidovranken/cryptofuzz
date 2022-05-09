all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o gf25519.o
	ar rcs module.a module.o gf25519.o
	ranlib module.a
gf25519.o:
	test $(BINGCD_PATH)
	$(CC) -march=native -c $(BINGCD_PATH)/src/gf25519.c
module.o: module.cpp module.h
	test $(BINGCD_PATH)
	$(CXX) $(CXXFLAGS) -I $(BINGCD_PATH)/src -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
