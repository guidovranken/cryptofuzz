all: module.a

CXXFLAGS += -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf module.a
	ar rcs module.a module.o
	ranlib module.a
harness.h : harness.js
	xxd -i harness.js >harness.h
module.o: module.cpp module.h harness.h
	test $(V8_EMBEDDED_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(V8_EMBEDDED_INCLUDE_PATH) -c module.cpp -o module.o
clean:
	rm -rf *.o module.a harness.h
