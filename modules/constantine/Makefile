all: module.a

CXXFLAGS += -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

#module.a: module.o libconstantine_harness.a cryptofuzz.a
module.a: module.o libconstantine_harness.a
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x ../libconstantine_harness.a
	#cd tmp && ar x ../cryptofuzz.a
	ar rcs module.a module.o tmp/*.o
	ranlib module.a
libconstantine_harness.a : constantine_harness.nim
	test $(NIM_PATH)
	test $(CONSTANTINE_PATH)
	$(NIM_PATH)/bin/nim c --threads:on -d:release --noMain --app:staticlib -d:noSignalHandler --maxLoopIterationsVM:100000000 --path:$(CONSTANTINE_PATH) --header:constantine_harness.h constantine_harness.nim
#module.o: libconstantine_harness.a module.cpp module.h cryptofuzz.a
module.o: libconstantine_harness.a module.cpp module.h
	$(CXX) $(CXXFLAGS) -I$(HOME)/.cache/nim/constantine_harness_r/ -I$(NIM_PATH)/lib/ -fPIC -c module.cpp -o module.o
cryptofuzz.a: cryptofuzz.go
	go build -o cryptofuzz.a -buildmode=c-archive cryptofuzz.go
clean:
	rm -rf *.o module.a cryptofuzz.a libconstantine_harness.a tmp/
