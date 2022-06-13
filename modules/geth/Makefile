all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o cryptofuzz.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp/ && ar x ../cryptofuzz.a && ar rcs ../module.a *.o ../module.o
	ranlib module.a
	rm -rf tmp/
cryptofuzz.a: cryptofuzz.go
	go build -o cryptofuzz.a -buildmode=c-archive cryptofuzz.go
module.o: module.cpp module.h cryptofuzz.a
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
