import java.util.Arrays;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.RIPEMD320Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.WNafL2RMultiplier;
import java.math.BigInteger;

public class CryptofuzzBouncyCastleHarness
{
    public static byte[] Digest(String hash, byte[] msg, int[] chunks)
    {
        Digest md;
        if ( hash.equals("SHA-1") ) {
            md = new SHA1Digest();
        } else if ( hash.equals("SHA-224") ) {
            md = new SHA224Digest();
        } else if ( hash.equals("SHA-256") ) {
            md = new SHA256Digest();
        } else if ( hash.equals("SHA-384") ) {
            md = new SHA384Digest();
        } else if ( hash.equals("SHA-512") ) {
            md = new SHA512Digest();
        } else if ( hash.equals("SHA3-224") ) {
            md = new SHA3Digest(224);
        } else if ( hash.equals("SHA3-256") ) {
            md = new SHA3Digest(256);
        } else if ( hash.equals("SHA3-384") ) {
            md = new SHA3Digest(384);
        } else if ( hash.equals("SHA3-512") ) {
            md = new SHA3Digest(512);
        } else if ( hash.equals("RIPEMD128") ) {
            md = new RIPEMD128Digest();
        } else if ( hash.equals("RIPEMD160") ) {
            md = new RIPEMD160Digest();
        } else if ( hash.equals("RIPEMD256") ) {
            md = new RIPEMD256Digest();
        } else if ( hash.equals("RIPEMD320") ) {
            md = new RIPEMD320Digest();
        } else if ( hash.equals("GOST3411") ) {
            md = new GOST3411Digest();
        } else if ( hash.equals("MD2") ) {
            md = new MD2Digest();
        } else if ( hash.equals("MD4") ) {
            md = new MD4Digest();
        } else if ( hash.equals("MD5") ) {
            md = new MD5Digest();
        } else if ( hash.equals("Tiger") ) {
            md = new TigerDigest();
        } else if ( hash.equals("Whirlpool") ) {
            md = new WhirlpoolDigest();
        } else if ( hash.equals("SM3") ) {
            md = new SM3Digest();
        } else if ( hash.equals("Keccak-224") ) {
            md = new KeccakDigest(224);
        } else if ( hash.equals("Keccak-256") ) {
            md = new KeccakDigest(256);
        } else if ( hash.equals("Keccak-384") ) {
            md = new KeccakDigest(384);
        } else if ( hash.equals("Keccak-512") ) {
            md = new KeccakDigest(512);
        } else if ( hash.equals("BLAKE2b-128") ) {
            md = new Blake2bDigest(128);
        } else if ( hash.equals("BLAKE2b-160") ) {
            md = new Blake2bDigest(160);
        } else if ( hash.equals("BLAKE2b-256") ) {
            md = new Blake2bDigest(256);
        } else if ( hash.equals("BLAKE2b-384") ) {
            md = new Blake2bDigest(384);
        } else if ( hash.equals("BLAKE2b-512") ) {
            md = new Blake2bDigest(512);
        } else if ( hash.equals("BLAKE2s-128") ) {
            md = new Blake2sDigest(128);
        } else if ( hash.equals("BLAKE2s-160") ) {
            md = new Blake2sDigest(160);
        } else if ( hash.equals("BLAKE2s-224") ) {
            md = new Blake2sDigest(224);
        } else if ( hash.equals("BLAKE2s-256") ) {
            md = new Blake2sDigest(256);
        } else if ( hash.equals("SHAKE256") ) {
            md = new SHAKEDigest();
        } else {
            throw new IllegalArgumentException("");
        }

        int curpos = 0;
        for (int i = 0; i < chunks.length; i++) {
            int cursize = chunks[i];
            md.update(
                    Arrays.copyOfRange(msg, curpos, curpos + cursize),
                    0,
                    cursize);
            curpos += cursize;
        }
        byte[] h = new byte[md.getDigestSize()];
        md.doFinal(h, 0);
        return h;
    }
    public static String ECC_Point_Add(
            String _curve,
            String _ax,
            String _ay,
            String _bx,
            String _by) {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(_curve);
        ECCurve curve = ecSpec.getCurve();

        BigInteger ax = new BigInteger(_ax);
        BigInteger ay = new BigInteger(_ay);
        ECPoint a = curve.createPoint(ax, ay);

        BigInteger bx = new BigInteger(_bx);
        BigInteger by = new BigInteger(_by);
        ECPoint b = curve.createPoint(bx, by);

        ECPoint result = a.add(b).normalize();

        BigInteger rx = result.getAffineXCoord().toBigInteger();
        BigInteger ry = result.getAffineYCoord().toBigInteger();

        return rx.toString() + " " + ry.toString();
    }

    public static String ECC_Point_Mul(
            String _curve,
            String _x,
            String _y,
            String _scalar,
            int multiplier) {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(_curve);
        ECCurve curve = ecSpec.getCurve();

        BigInteger x = new BigInteger(_x);
        BigInteger y = new BigInteger(_y);
        ECPoint point = curve.createPoint(x, y);

        BigInteger scalar = new BigInteger(_scalar);

        ECPoint result;
        if ( multiplier == 0 ) {
            FixedPointCombMultiplier m = new FixedPointCombMultiplier();
            result = m.multiply(point, scalar).normalize();
        } else if ( multiplier == 1 ) {
            WNafL2RMultiplier m = new WNafL2RMultiplier();
            result = m.multiply(point, scalar).normalize();
        } else {
            result = point.multiply(scalar);
        }

        BigInteger rx = result.getAffineXCoord().toBigInteger();
        BigInteger ry = result.getAffineYCoord().toBigInteger();

        return rx.toString() + " " + ry.toString();
    }
}
