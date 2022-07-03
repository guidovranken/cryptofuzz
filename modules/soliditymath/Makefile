all: module.a cryptofuzz.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf tmp/
	mkdir tmp/
	cd tmp/ && ar x ../cryptofuzz.a && ar rcs ../module.a *.o ../module.o
	ranlib module.a
	rm -rf tmp/
cryptofuzz.a: cryptofuzz.go
	go build -o cryptofuzz.a -buildmode=c-archive cryptofuzz.go
module.o: cryptofuzz.a module.cpp module.h contracts.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o

github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.sol :
	wget 'https://raw.githubusercontent.com/Uniswap/uniswap-v3-core/main/contracts/libraries/FullMath.sol' -O github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.sol
LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.json : LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.sol github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.sol solc-linux-amd64-v0.7.6+commit.7338295f
	./solc-linux-amd64-v0.7.6+commit.7338295f LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.sol --combined-json hashes,bin-runtime >LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.json

github.com-Uniswap-lib-master-contracts-libraries-FullMath.sol :
	wget 'https://raw.githubusercontent.com/Uniswap/uniswap-lib/master/contracts/libraries/FullMath.sol' -O github.com-Uniswap-lib-master-contracts-libraries-FullMath.sol
LOADER-github.com-Uniswap-lib-master-contracts-libraries-FullMath.json : LOADER-github.com-Uniswap-lib-master-contracts-libraries-FullMath.sol github.com-Uniswap-lib-master-contracts-libraries-FullMath.sol solc-linux-amd64-v0.7.6+commit.7338295f
	./solc-linux-amd64-v0.7.6+commit.7338295f LOADER-github.com-Uniswap-lib-master-contracts-libraries-FullMath.sol --combined-json hashes,bin-runtime >LOADER-github.com-Uniswap-lib-master-contracts-libraries-FullMath.json

#github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.sol :
#	wget 'https://raw.githubusercontent.com/sushiswap/sushiswap/master/contracts/uniswapv2/libraries/Math.sol' -O github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.sol
#LOADER-github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.json : LOADER-github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.sol github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.sol solc-linux-amd64-v0.6.12+commit.27d51765
#	./solc-linux-amd64-v0.6.12+commit.27d51765 LOADER-github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.sol --combined-json hashes,bin-runtime >LOADER-github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.json

github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.sol :
	wget 'https://raw.githubusercontent.com/Uniswap/uniswap-v3-core/main/contracts/libraries/BitMath.sol' -O github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.sol
LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.json : LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.sol github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.sol solc-linux-amd64-v0.7.6+commit.7338295f
	./solc-linux-amd64-v0.7.6+commit.7338295f LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.sol --combined-json hashes,bin-runtime >LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.json

github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.sol :
	wget 'https://raw.githubusercontent.com/Uniswap/uniswap-v3-core/main/contracts/libraries/LowGasSafeMath.sol' -O github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.sol
LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.json : LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.sol github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.sol solc-linux-amd64-v0.7.6+commit.7338295f
	./solc-linux-amd64-v0.7.6+commit.7338295f LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.sol --combined-json hashes,bin-runtime >LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.json

github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.sol :
	wget 'https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/contracts/utils/math/Math.sol' -O github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.sol
LOADER-github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.json : LOADER-github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.sol github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.sol solc-linux-amd64-v0.8.0+commit.c7dfd78e
	./solc-linux-amd64-v0.8.0+commit.c7dfd78e LOADER-github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.sol --combined-json hashes,bin-runtime >LOADER-github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.json

github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.sol :
	wget 'https://raw.githubusercontent.com/Uniswap/solidity-lib/master/contracts/libraries/Babylonian.sol' -O github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.sol
LOADER-github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.json : LOADER-github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.sol github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.sol solc-linux-amd64-v0.6.12+commit.27d51765
	./solc-linux-amd64-v0.6.12+commit.27d51765 LOADER-github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.sol --combined-json hashes,bin-runtime >LOADER-github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.json

LOADER-github.com-bancorprotocol-contracts-v3-blob-master-contracts-utility-MathEx.json : LOADER-github.com-bancorprotocol-contracts-v3-blob-master-contracts-utility-MathEx.sol solc-linux-amd64-v0.8.13+commit.abaa5c0e
	./solc-linux-amd64-v0.8.13+commit.abaa5c0e LOADER-github.com-bancorprotocol-contracts-v3-blob-master-contracts-utility-MathEx.sol --combined-json hashes,bin-runtime >LOADER-github.com-bancorprotocol-contracts-v3-blob-master-contracts-utility-MathEx.json

Coinmonks.json : Coinmonks.sol solc-linux-amd64-v0.7.0+commit.9e61f92b
	./solc-linux-amd64-v0.7.0+commit.9e61f92b Coinmonks.sol --combined-json hashes,bin-runtime >Coinmonks.json

solc-linux-amd64-v0.8.13+commit.abaa5c0e :
	wget 'https://github.com/ethereum/solc-bin/raw/gh-pages/linux-amd64/solc-linux-amd64-v0.8.13+commit.abaa5c0e' -O solc-linux-amd64-v0.8.13+commit.abaa5c0e
	chmod +x solc-linux-amd64-v0.8.13+commit.abaa5c0e
solc-linux-amd64-v0.8.0+commit.c7dfd78e :
	wget 'https://github.com/ethereum/solc-bin/raw/gh-pages/linux-amd64/solc-linux-amd64-v0.8.0+commit.c7dfd78e' -O solc-linux-amd64-v0.8.0+commit.c7dfd78e
	chmod +x solc-linux-amd64-v0.8.0+commit.c7dfd78e
solc-linux-amd64-v0.7.6+commit.7338295f :
	wget 'https://github.com/ethereum/solc-bin/raw/gh-pages/linux-amd64/solc-linux-amd64-v0.7.6%2Bcommit.7338295f' -O solc-linux-amd64-v0.7.6+commit.7338295f
	chmod +x solc-linux-amd64-v0.7.6+commit.7338295f
solc-linux-amd64-v0.6.12+commit.27d51765 :
	wget 'https://github.com/ethereum/solc-bin/raw/gh-pages/linux-amd64/solc-linux-amd64-v0.6.12+commit.27d51765' -O solc-linux-amd64-v0.6.12+commit.27d51765
	chmod +x solc-linux-amd64-v0.6.12+commit.27d51765
solc-linux-amd64-v0.7.0+commit.9e61f92b :
	wget 'https://github.com/ethereum/solc-bin/raw/gh-pages/linux-amd64/solc-linux-amd64-v0.7.0+commit.9e61f92b' -O solc-linux-amd64-v0.7.0+commit.9e61f92b
	chmod +x solc-linux-amd64-v0.7.0+commit.9e61f92b

contracts.h : \
	sol-json-to-h.py \
	LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.json \
	LOADER-github.com-Uniswap-lib-master-contracts-libraries-FullMath.json \
	LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.json \
	LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.json \
	LOADER-github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.json \
	LOADER-github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.json \
	LOADER-github.com-bancorprotocol-contracts-v3-blob-master-contracts-utility-MathEx.json \
	Coinmonks.json
	./sol-json-to-h.py \
		LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.json \
		LOADER-github.com-Uniswap-lib-master-contracts-libraries-FullMath.json \
		LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.json \
		LOADER-github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.json \
		LOADER-github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.json \
		LOADER-github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.json \
		LOADER-github.com-bancorprotocol-contracts-v3-blob-master-contracts-utility-MathEx.json \
		Coinmonks.json

clean:
	rm -rf github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.sol
	rm -rf github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.sol
	rm -rf github.com-Uniswap-v3-core-main-contracts-libraries-FullMath.sol
	rm -rf github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.sol
	rm -rf github.com-Uniswap-lib-master-contracts-libraries-FullMath.sol
	rm -rf github.com-Uniswap-solidity-lib-blob-master-contracts-libraries-Babylonian.sol
	rm -rf *.json
	rm -rf solc-linux-amd64-v0.8.13+commit.abaa5c0e
	rm -rf solc-linux-amd64-v0.8.0+commit.c7dfd78e
	rm -rf solc-linux-amd64-v0.7.6+commit.7338295f
	rm -rf solc-linux-amd64-v0.6.12+commit.27d51765
	rm -rf *.o module.a cryptofuzz.a cryptofuzz.h contracts.h
