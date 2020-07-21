all : cryptofuzz generate_dict generate_corpus

CXXFLAGS += -Wall -Wextra -std=c++17 -I include/ -I . -I fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

driver.o : driver.cpp
	$(CXX) $(CXXFLAGS) driver.cpp -c -o driver.o
executor.o : executor.cpp
	$(CXX) $(CXXFLAGS) executor.cpp -c -o executor.o
util.o : util.cpp
	$(CXX) $(CXXFLAGS) util.cpp -c -o util.o
entry.o : entry.cpp
	$(CXX) $(CXXFLAGS) entry.cpp -c -o entry.o
operation.o : operation.cpp
	$(CXX) $(CXXFLAGS) operation.cpp -c -o operation.o
tests.o : tests.cpp
	$(CXX) $(CXXFLAGS) tests.cpp -c -o tests.o
datasource.o : datasource.cpp
	$(CXX) $(CXXFLAGS) datasource.cpp -c -o datasource.o
repository_tbl.h : gen_repository.py
	python gen_repository.py
repository.o : repository.cpp repository_tbl.h
	$(CXX) $(CXXFLAGS) repository.cpp -c -o repository.o
options.o : options.cpp
	$(CXX) $(CXXFLAGS) options.cpp -c -o options.o

third_party/cpu_features/build/libcpu_features.a :
	cd third_party/cpu_features && rm -rf build && mkdir build && cd build && cmake .. && make

cryptofuzz : driver.o executor.o util.o entry.o tests.o operation.o datasource.o repository.o options.o third_party/cpu_features/build/libcpu_features.a
	test $(LIBFUZZER_LINK)
	#$(CXX) $(CXXFLAGS) driver.o executor.o util.o entry.o tests.o operation.o datasource.o modules/openssl/module.a modules/mbedtls/module.a modules/boost/module.a modules/publicdomain/module.a modules/cppcrypto/module.a modules/monero/module.a Fuzzer/libFuzzer.a -o cryptofuzz
	$(CXX) $(CXXFLAGS) driver.o executor.o util.o entry.o tests.o operation.o datasource.o repository.o options.o $(shell find modules -type f -name module.a) $(LIBFUZZER_LINK) third_party/cpu_features/build/libcpu_features.a $(LINK_FLAGS) -o cryptofuzz

generate_dict: generate_dict.cpp
	$(CXX) $(CXXFLAGS) generate_dict.cpp -o generate_dict

generate_corpus: generate_corpus.cpp
	$(CXX) $(CXXFLAGS) generate_corpus.cpp -o generate_corpus

clean:
	rm -rf driver.o executor.o util.o entry.o operation.o tests.o datasource.o repository.o repository_tbl.h cryptofuzz generate_dict generate_corpus
