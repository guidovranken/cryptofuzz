all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o v8-bigint/
	rm -rf module.a
	ar rcs module.a module.o v8-bigint/*
	ranlib module.a
v8-bigint/ :
	rm -rf v8-bigint/
	mkdir v8-bigint/
	cd v8-bigint/ && $(CXX) $(CXXFLAGS) -DV8_ADVANCED_BIGINT_ALGORITHMS -I $(V8_PATH) $(V8_PATH)/src/bigint/*.cc -c
module.o: module.cpp module.h
	test $(V8_PATH)
	$(CXX) $(CXXFLAGS) -DV8_ADVANCED_BIGINT_ALGORITHMS -I $(V8_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a v8-bigint/
