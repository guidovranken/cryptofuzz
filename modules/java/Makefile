all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o CryptofuzzJavaHarness.class
	ar rcs module.a module.o
	ranlib module.a
CryptofuzzJavaHarness.class : CryptofuzzJavaHarness.java
	test $(JDK_PATH)
	$(JDK_PATH)/bin/javac CryptofuzzJavaHarness.java
module.o: module.cpp module.h
	test $(JDK_PATH)
	$(CXX) $(CXXFLAGS) -I $(JDK_PATH)/include/ -I $(JDK_PATH)/include/linux/ -DCLASS_PATH="\"$(realpath .)\"" -c module.cpp -o module.o
clean:
	rm -rf *.o module.a CryptofuzzJavaHarness.class
