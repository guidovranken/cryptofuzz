all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL
RUSTFLAGS := "--cfg fuzzing -Cdebug-assertions -Cdebuginfo=1 -Cforce-frame-pointers -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-trace-geps -Cllvm-args=-sanitizer-coverage-prune-blocks=0 -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth -Ccodegen-units=1"

module.a: module.o ./target/x86_64-unknown-linux-gnu/debug/libring_cryptofuzz.a
	bash ../link.sh module.a ./target/x86_64-unknown-linux-gnu/debug/libring_cryptofuzz.a
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
src/ids.rs: generate_ids
	./generate_ids
target/x86_64-unknown-linux-gnu/debug/libring_cryptofuzz.a: src/lib.rs src/ids.rs
	RUSTFLAGS=$(RUSTFLAGS) cargo build --target x86_64-unknown-linux-gnu
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
	cargo clean
