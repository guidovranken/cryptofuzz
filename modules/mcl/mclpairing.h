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

        const auto parts = mcl_detail::splitPubkeyStr(pub.getStr(10));
        if ( parts.size() != 3 ) {
            abort();
        }
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
