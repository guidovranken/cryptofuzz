p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
starkp = 2**251 + 17*2**192 + 1


def ufq12mul():
    for i in range(12):
        for j in range(12):
            tmp = f"let ab{i:X}{j:X} = bigint_mul(a.e{i:X}, b.e{j:X})"
            print(tmp)
    print("let res = UnreducedFQ23(")
    for sum_ij in range(23):
        tmp_sum = []
        for j in range(12):
            i = sum_ij - j
            if i > 11 or i < 0: continue
            tmp_sum.append(f'ab{i:X}{j:X}')
        
        print(f'e{sum_ij:02X}=UnreducedBigInt5(')
        print(f"\td0={'.d0 + '.join(tmp_sum)}.d0,")
        print(f"\td1={'.d1 + '.join(tmp_sum)}.d1,")
        print(f"\td2={'.d2 + '.join(tmp_sum)}.d2,")
        print(f"\td3={'.d3 + '.join(tmp_sum)}.d3,")
        print(f"\td4={'.d4 + '.join(tmp_sum)}.d4),")

    print(')')

def def_struct_ufq23():
    for i in range(23):
        print(f'member e{i:02X} : UnreducedBigInt5')

ufq12mul()
# def_struct_ufq23()

exit()


maxX, maxY = divmod(p, starkp)

# Representing n < p and [x,y] 
#  0 <= x <= maxX (6)
#  0 <= y <= starkp
#  y <  maxY if x == maxP
def rp(n):
    """returns the represetation of n"""
    n = n % p
    x,y = divmod(n, starkp)
    assert x <= maxX
    if x == maxX: assert y < maxY
    return [x,y]

print(maxX, maxY)
print(rp(0))
print(rp(1))
print(rp(-1))
print(rp(starkp-1))
print(rp(starkp))
print(rp(starkp+1))

