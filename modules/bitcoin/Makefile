all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o ctaes.o
	ar rcs module.a module.o ctaes.o
	ranlib module.a
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
ctaes.o : ctaes.c ctaes.h
	$(CC) $(CFLAGS) -fPIC -c ctaes.c -o ctaes.o 
clean:
	rm -rf *.o module.a
