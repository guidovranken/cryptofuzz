# ff-cairo
An Cairo implementation of finite field operations.

# GOAL

Our goal is to use Hints as little as possible. Actually, we only used Hints in two functions.

## Design

We use `BigInt3` as a unique representation of a big number, but `unreduceBigInt3` to represent a big number with limbs in `[-k\*BASE, k\*BASE]` and `unreduceBigInt5` with limbs in `[-k\*BASE^2, k\*BASE^2]`.

Function `bigint_div_mod` is the one of the functions which use hints, it computes `x/y^2 mod p`. `x` is `unreduceBigInt5` and `y` is `unreduceBigInt3`, return a `BigInt3`.

Other field computions can be done by calling this function.

For example,  `bigint_div_mul` can be `x\*y/1 mod p`, with `x`, `y` are `unreduceBigInt3`.

## Use examples
See [common-ec-cairo](https://github.com/EulerSmile/common-ec-cairo) for how to use this library.

## License
[MIT License](https://opensource.org/licenses/MIT) © EulerSmile