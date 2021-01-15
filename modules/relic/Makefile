all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o bn_helper.o bn_ops.o
	test $(RELIC_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(RELIC_PATH)/build/lib/librelic_s.a
	ar rcs module.a module.o bn_helper.o bn_ops.o tmp/*
	ranlib module.a
module.o: module.cpp module.h
	test $(RELIC_PATH)
	$(CXX) $(CXXFLAGS) -I $(RELIC_PATH)/include -I $(RELIC_PATH)/build/include -fPIC -c module.cpp -o module.o
bn_helper.o: bn_helper.cpp bn_helper.h
	test $(RELIC_PATH)
	$(CXX) $(CXXFLAGS) -I $(RELIC_PATH)/include -I $(RELIC_PATH)/build/include -c bn_helper.cpp -o bn_helper.o
bn_ops.o: bn_ops.cpp bn_ops.h
	test $(RELIC_PATH)
	$(CXX) $(CXXFLAGS) -I $(RELIC_PATH)/include -I $(RELIC_PATH)/build/include -c bn_ops.cpp -o bn_ops.o
clean:
	rm -rf *.o module.a
