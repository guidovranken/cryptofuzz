all : cryptofuzz generate_dict generate_corpus

CXXFLAGS += -Wall -Wextra -std=c++17 -I include/ -I . -DFUZZING_HEADERS_NO_IMPL

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

cryptofuzz : driver.o executor.o util.o entry.o tests.o operation.o datasource.o
	test $(LIBFUZZER_LINK)
	#$(CXX) $(CXXFLAGS) driver.o executor.o util.o entry.o tests.o operation.o datasource.o modules/openssl/module.a modules/mbedtls/module.a modules/boost/module.a modules/publicdomain/module.a modules/cppcrypto/module.a modules/monero/module.a Fuzzer/libFuzzer.a -o cryptofuzz
	$(CXX) $(CXXFLAGS) driver.o executor.o util.o entry.o tests.o operation.o datasource.o modules/openssl/module.a $(LIBFUZZER_LINK) -o cryptofuzz

generate_dict: generate_dict.cpp
	$(CXX) $(CXXFLAGS) generate_dict.cpp -o generate_dict

generate_corpus: generate_corpus.cpp
	$(CXX) $(CXXFLAGS) generate_corpus.cpp -o generate_corpus

clean:
	rm -rf driver.o executor.o util.o entry.o operation.o tests.o datasource.o cryptofuzz generate_dict
