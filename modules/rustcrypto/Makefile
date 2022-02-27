all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL
RUSTFLAGS := "--cfg fuzzing -Cdebug-assertions -Cdebuginfo=1 -Cforce-frame-pointers -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-trace-geps -Cllvm-args=-sanitizer-coverage-prune-blocks=0 -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth -Ccodegen-units=1"

module.a: module.o target/x86_64-unknown-linux-gnu/release/libcryptofuzz_rustcrypto_hashes.a
	bash ../link.sh module.a ./target/x86_64-unknown-linux-gnu/release/libcryptofuzz_rustcrypto_hashes.a
	ranlib module.a
target/x86_64-unknown-linux-gnu/release/libcryptofuzz_rustcrypto_hashes.a : generate_ids src/lib.rs Cargo.toml
	./generate_ids
	test ids.rs
	mv ids.rs src/
	RUSTFLAGS=$(RUSTFLAGS) cargo build --release --target x86_64-unknown-linux-gnu
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) -O0 generate_ids.cpp -o generate_ids
module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a generate_ids target/
