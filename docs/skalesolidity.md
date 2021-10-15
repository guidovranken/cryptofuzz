```
git clone --depth 1 https://github.com/skalenetwork/skale-manager.git
cp cryptofuzz/modules/skalesolidity/Cryptofuzz.sol skale-manager/contracts/
cd skale-manager/
yarn
export SKALE_CRYPTOFUZZ_SOL_JSON=$(realpath artifacts/contracts/Cryptofuzz.sol/Cryptofuzz.json)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SKALE_SOLIDITY"
cd ../
```
