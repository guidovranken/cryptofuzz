all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(MCL_LIBMCL_A_PATH)
	bash ../link.sh module.a $(MCL_LIBMCL_A_PATH)
	ranlib module.a
module.o: module.cpp module.h mclpairing.h
	test $(MCL_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(MCL_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
