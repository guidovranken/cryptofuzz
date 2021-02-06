all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(CHIA_BLS_LIBBLS_A_PATH)
	bash ../link.sh module.a $(CHIA_BLS_LIBBLS_A_PATH)
	ranlib module.a
module.o: module.cpp module.h
	test $(CHIA_BLS_INCLUDE_PATH)
	test $(CHIA_BLS_RELIC_INCLUDE_PATH_1)
	test $(CHIA_BLS_RELIC_INCLUDE_PATH_2)
	$(CXX) $(CXXFLAGS) -I $(CHIA_BLS_INCLUDE_PATH) -I $(CHIA_BLS_RELIC_INCLUDE_PATH_1) -I $(CHIA_BLS_RELIC_INCLUDE_PATH_2) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
