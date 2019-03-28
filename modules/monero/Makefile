all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o jh.o groestl.o
	ar rcs module.a module.o jh.o groestl.o
	ranlib module.a
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
jh.o : jh.c jh.h
	$(CC) $(CFLAGS) -fPIC -c jh.c -o jh.o 
groestl.o : groestl.c groestl.h
	$(CC) $(CFLAGS) -fPIC -c groestl.c -o groestl.o 
clean:
	rm -rf *.o module.a
