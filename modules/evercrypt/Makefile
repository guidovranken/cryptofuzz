all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(EVERCRYPT_A_PATH)
	bash ../link.sh module.a $(EVERCRYPT_A_PATH) $(KREMLIN_A_PATH)
	ranlib module.a
module.o: module.cpp module.h
	test $(EVERCRYPT_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(EVERCRYPT_INCLUDE_PATH) -I $(KREMLIN_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
