all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o uECC.o
	rm -rf module.a
	ar rcs module.a module.o uECC.o
	ranlib module.a
uECC.o: $(MICRO_ECC_PATH)/uECC.c
	$(CC) $(CFLAGS) -I $(MICRO_ECC_PATH) -fPIC -c $(MICRO_ECC_PATH)/uECC.c -o uECC.o
module.o: module.cpp module.h
	test $(MICRO_ECC_PATH)
	$(CXX) $(CXXFLAGS) -I $(MICRO_ECC_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
