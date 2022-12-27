all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o cryptofuzz.o
	ar rcs module.a module.o cryptofuzz.o
	ranlib module.a
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -I -fPIC -c module.cpp -o module.o
cryptofuzz.bc : cryptofuzz.zig
	test $(ZIG_BIN)
	#$(ZIG_BIN) build-lib -O ReleaseFast -fcompiler-rt cryptofuzz.zig
	$(ZIG_BIN) build-lib -femit-llvm-bc=cryptofuzz.bc -fno-stack-check -mcpu=x86_64 cryptofuzz.zig
cryptofuzz.o : cryptofuzz.bc
	$(ZIG_BIN) cc -c $(CFLAGS) -mcpu=x86_64 cryptofuzz.bc

clean:
	rm -rf *.o module.a
