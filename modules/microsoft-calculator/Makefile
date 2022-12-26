all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o 
	cd $(MICROSOFT_CALCULATOR_PATH)/src/CalcManager/Ratpack/ && $(CXX) $(CXXFLAGS) -I $(MICROSOFT_CALCULATOR_PATH)/src/CalcManager/ -c $(MICROSOFT_CALCULATOR_PATH)/src/CalcManager/Ratpack/*.cpp
	ar rcs module.a module.o $(MICROSOFT_CALCULATOR_PATH)/src/CalcManager/Ratpack/*.o
	ranlib module.a
module.o: module.cpp module.h
	test $(MICROSOFT_CALCULATOR_PATH)
	$(CXX) $(CXXFLAGS) -I $(MICROSOFT_CALCULATOR_PATH)/src/CalcManager/ -I $(MICROSOFT_CALCULATOR_PATH)/src/CalcManager/Ratpack/ -c module.cpp -o module.o
clean:
	rm -rf *.o module.a target/
