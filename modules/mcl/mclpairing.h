void Hash(G1& P, const std::string& m)
{
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}

void Sign(G1& sign, const Fr& s, const std::string& m)
{
    G1 Hm;
    Hash(Hm, m);
    G1::mul(sign, Hm, s); // sign = s H(m)
}

std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    std::optional<component::BLS_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        static const
            G1 P(   Fp("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10),
                    Fp("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10) );

        Fr sec;
        sec.setStr(op.priv.ToString(ds), 10);

        G1 pub;
        G1::mul(pub, P, sec);

        const auto parts = mcl_detail::split(pub.getStr(10), 3);
        ret = { parts[1], parts[2] };
    } catch ( cybozu::Exception ) { }

    return ret;
}

std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op) {

    std::optional<component::BLS_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    try {
        Fr sec;
        sec.setStr(op.priv.ToString(ds), 10);

        G1 sign;
        Sign(sign, sec, std::string(op.cleartext.GetPtr(), op.cleartext.GetPtr() + op.cleartext.GetSize()));
    } catch ( cybozu::Exception ) { }

    return ret;
}

std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
#if 0
        G1 signature(
                Fp(op.signature.first.ToString(ds), 10),
                Fp(op.signature.first.ToString(ds), 10) );

        G1 pub(
                Fp(op.pub.first.ToString(ds), 10),
                Fp(op.pub.third.ToString(ds), 10));

        ret = Verify(signature, Q, pub, std::string(op.cleartext.GetPtr(), op.cleartext.GetPtr() + op.cleartext.GetSize()));
#endif
    } catch ( cybozu::Exception ) { }

    return ret;
}

std::optional<component::G1> OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    std::optional<component::G1> ret = std::nullopt;

    try {
        G1 P;
        /* noret */ hashAndMapToG1(P, op.cleartext.GetPtr(), op.cleartext.GetSize());
        const auto parts = mcl_detail::split(P.getStr(10), 3);
        ret = { parts[1], parts[2] };
    } catch ( cybozu::Exception ) { }

    return ret;
}

std::optional<component::G2> OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    std::optional<component::G2> ret = std::nullopt;

    try {
        G2 P;
        /* noret */ hashAndMapToG2(P, op.cleartext.GetPtr(), op.cleartext.GetSize());
        const auto parts = mcl_detail::split(P.getStr(10), 5);
        ret = { parts[1], parts[2], parts[3], parts[4] };
    } catch ( cybozu::Exception ) { }

    return ret;
}

std::optional<bool> OpBLS_Pairing(operation::BLS_Pairing& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        G1 P;
        G2 Q;
        if ( op.hashInput != std::nullopt ) {
            {
                auto blsHashToG1Modifier = ds.GetData(0);
                operation::BLS_HashToG1 opBLSHashToG1(
                        op.curveType,
                        *op.hashInput,
                        component::Modifier(blsHashToG1Modifier.data(), blsHashToG1Modifier.size()));

                auto p = OpBLS_HashToG1(opBLSHashToG1);
                if ( p == std::nullopt ) {
                    return std::nullopt;
                }

                P = G1(
                        Fp(p->first.ToString(ds), 10),
                        Fp(p->second.ToString(ds), 10));
            }

            {
                auto blsHashToG2Modifier = ds.GetData(0);
                operation::BLS_HashToG2 opBLSHashToG2(
                        op.curveType,
                        *op.hashInput,
                        component::Modifier(blsHashToG2Modifier.data(), blsHashToG2Modifier.size()));

                auto q = OpBLS_HashToG2(opBLSHashToG2);
                if ( q == std::nullopt ) {
                    return std::nullopt;
                }

                Q = G2(
                        Fp2(q->first.first.ToString(ds), q->first.second.ToString(ds), 10),
                        Fp2(q->second.first.ToString(ds), q->second.second.ToString(ds), 10));
            }

        } else {
            P = G1(
                    Fp(op.q.first.ToString(ds), 10),
                    Fp(op.q.second.ToString(ds), 10));
            Q = G2(
                    Fp2(op.p.first.first.ToString(ds), op.p.first.second.ToString(ds), 10),
                    Fp2(op.p.second.first.ToString(ds), op.p.second.second.ToString(ds), 10));
        }

        Fp12 f;
        pairing(f, P, Q);
        const auto parts = mcl_detail::split(f.getStr(10), 12);
    }
    catch ( cybozu::Exception ) { }
    catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    return ret;
}
