all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o cpu.o
	ar rcs module.a module.o cpu.o
	ranlib module.a
cpu.o : cpu.asm
	nasm cpu.asm -f elf64
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -I -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
