all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(BLST_LIBBLST_A_PATH)
	bash ../link.sh module.a $(BLST_LIBBLST_A_PATH)
	ranlib module.a
module.o: module.cpp module.h
	test $(BLST_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(BLST_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
