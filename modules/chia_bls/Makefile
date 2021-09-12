all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(CHIA_BLS_LIBBLS_A_PATH)
	test $(CHIA_BLS_LIBRELIC_S_A_PATH)
	test $(CHIA_BLS_LIBSODIUM_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(CHIA_BLS_LIBBLS_A_PATH)
	cd tmp && ar x $(CHIA_BLS_LIBRELIC_S_A_PATH)
	cd tmp && ar x $(CHIA_BLS_LIBSODIUM_A_PATH)
	ar rcs module.a module.o tmp/*
	ranlib module.a
module.o: module.cpp module.h
	test $(CHIA_BLS_INCLUDE_PATH)
	test $(CHIA_BLS_RELIC_INCLUDE_PATH_1)
	test $(CHIA_BLS_RELIC_INCLUDE_PATH_2)
	$(CXX) $(CXXFLAGS) -I $(CHIA_BLS_INCLUDE_PATH) -I $(CHIA_BLS_RELIC_INCLUDE_PATH_1) -I $(CHIA_BLS_RELIC_INCLUDE_PATH_2) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
