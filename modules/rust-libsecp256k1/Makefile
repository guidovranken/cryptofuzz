all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	bash ../link.sh module.a ./target/x86_64-unknown-linux-gnu/debug/librust_libsecp256k1.a
	ranlib module.a
target/debug/librust_libsecp256k1.a :
	cargo build --target x86_64-unknown-linux-gnu
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
