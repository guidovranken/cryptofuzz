all: module.a cryptofuzz.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf tmp/
	mkdir tmp/
	cd tmp/ && ar x ../cryptofuzz.a && ar rcs ../module.a *.o ../module.o
	ranlib module.a
	rm -rf tmp/
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.go : generate_ids
	./generate_ids
cryptofuzz.a: cryptofuzz.go ids.go
	go build -o cryptofuzz.a -buildmode=c-archive cryptofuzz.go ids.go
module.o: cryptofuzz.a module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a cryptofuzz.a cryptofuzz.h generate_ids ids.go
