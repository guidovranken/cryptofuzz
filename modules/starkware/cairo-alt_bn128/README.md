# Cairo implementation of alt_bn128 
## What is alt_bn128?
alt_bn128 is a pairing-friendly elliptic curve that can be used to verify computations done by snarks.

We implement the pairing function based on the code from [this repository.](https://github.com/ethereum/py_pairing/)

## How to run?
Make sure you are inside a Cairo virtual environment
```
make
```

## TODO
Hint verifications for pairing-related functions on FQ12