all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o bn_ops.o
	test $(NSS_NSPR_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnss_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libcertdb.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libpk11wrap_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libsoftokn_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libcerthi.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libcryptohi.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnsspki.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnssb.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnssdev.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnssutil.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libplds4.a && \
	ar x $(NSS_NSPR_PATH)/nspr/Debug/pr/src/libnspr4.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libplc4.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnss_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libsha-x86_c_lib.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libfreebl_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libhw-acc-crypto-avx.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libhw-acc-crypto-avx2.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libgcm-aes-x86_c_lib.a

	ar rcs module.a module.o bn_ops.o tmp/*.o
	rm -rf tmp/
	ranlib module.a
poc : poc.cpp
	test $(NSS_NSPR_PATH)
	$(CXX) $(CXXFLAGS) \
		-I $(NSS_NSPR_PATH)/dist/public/nss \
		-I $(NSS_NSPR_PATH)/dist/Debug/include/nspr \
		-I $(NSS_NSPR_PATH)/nss/lib/freebl \
		-I $(NSS_NSPR_PATH)/nss/lib/freebl/mpi \
		-I $(NSS_NSPR_PATH)/nss/lib/pk11wrap \
		-I $(NSS_NSPR_PATH)/nss/cpputil \
		poc.cpp \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libnss_static.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libcertdb.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libpk11wrap_static.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libsoftokn_static.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libcerthi.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libcryptohi.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libnsspki.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libnssb.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libnssdev.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libnssutil.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libplds4.a \
		$(NSS_NSPR_PATH)/nspr/Debug/pr/src/libnspr4.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libplc4.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libnss_static.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libfreebl_static.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libhw-acc-crypto-avx.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libhw-acc-crypto-avx2.a \
		$(NSS_NSPR_PATH)/dist/Debug/lib/libgcm-aes-x86_c_lib.a \
		-lsqlite3 \
		-o poc
bn_ops.o: bn_ops.cpp bn_ops.h
	test $(NSS_NSPR_PATH)
	$(CXX) $(CXXFLAGS) -I $(NSS_NSPR_PATH)/dist/public/nss -I $(NSS_NSPR_PATH)/dist/Debug/include/nspr -I $(NSS_NSPR_PATH)/nss/lib/freebl -I $(NSS_NSPR_PATH)/nss/lib/freebl/mpi -c bn_ops.cpp -o bn_ops.o
module.o: module.cpp module.h bn_ops.h
	test $(NSS_NSPR_PATH)
	$(CXX) $(CXXFLAGS) -I $(NSS_NSPR_PATH)/dist/public/nss -I $(NSS_NSPR_PATH)/dist/Debug/include/nspr -I $(NSS_NSPR_PATH)/nss/lib/freebl -I $(NSS_NSPR_PATH)/nss/lib/pk11wrap -I $(NSS_NSPR_PATH)/nss/cpputil -fPIC -c module.cpp -o module.o

clean:
	rm -rf *.o module.a
