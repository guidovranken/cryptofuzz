all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o libcryptofuzz.a
	rm -rf libcryptofuzz/
	mkdir libcryptofuzz/
	cp libcryptofuzz.a libcryptofuzz/module.a
	ar rcs module.a module.o
	ranlib module.a
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -I -fPIC -c module.cpp -o module.o
libcryptofuzz.a : cryptofuzz.zig
	test $(ZIG_BIN)
	#$(ZIG_BIN) build-lib -O ReleaseFast -fcompiler-rt cryptofuzz.zig
	$(ZIG_BIN) build-lib -fcompiler-rt cryptofuzz.zig

clean:
	rm -rf *.o module.a
