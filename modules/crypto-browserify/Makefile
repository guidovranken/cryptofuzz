all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBFUZZER_JS_PATH)/quickjs/libquickjs.a
	ar rcs module.a module.o $(LIBFUZZER_JS_PATH)/js.o tmp/*
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
node_modules :
	rm -rf node_modules/
	mkdir node_modules/
	#npm install browserify crypto-browserify
	npm install browserify
combined.js : harness.js ids.js
	cat ids.js harness.js >combined.js
bundle.js: combined.js node_modules
	nodejs ./node_modules/browserify/bin/cmd.js combined.js >bundle.js
crypto-browserify.bytecode : bundle.js
	test $(LIBFUZZER_JS_PATH)
	rm -rf crypto-browserify.bytecode
	$(LIBFUZZER_JS_PATH)/to_bytecode bundle.js crypto-browserify.bytecode
crypto-browserify.bytecode.h : crypto-browserify.bytecode
	xxd -i crypto-browserify.bytecode >crypto-browserify.bytecode.h
module.o: module.cpp module.h crypto-browserify.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o combined.js crypto-browserify.bytecode  crypto-browserify.bytecode.h ids.js bundle.js module.a generate_ids node_modules/ tmp/
