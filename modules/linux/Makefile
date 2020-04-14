all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(LIBKCAPI_A_PATH)
	bash ../link.sh module.a $(LIBKCAPI_A_PATH)
	ranlib module.a
module.o: module.cpp module.h
	test $(LIBKCAPI_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBKCAPI_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
