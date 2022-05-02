#!/usr/bin/python3

BASE = 2 ** 86

# number that need to split into 3 limbs.
# G = G0 + G1 * BASE + G2 * BASE ^ 2
G = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

x = divmod(G, BASE)
y = divmod(x[0], BASE)

G0 = x[1]
G1 = y[1]
G2 = y[0]

# G0, G1, G2 are 3 limbs we want in range [0, BASE).
print("( ", hex(G0), ", ", hex(G1), ", ", hex(G2), ")")