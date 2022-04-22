import java.math.BigInteger;

public class CryptofuzzJavaHarness
{
  public static boolean ECDSA_Verify(String hash, String curve, String _x, String _y, String _r, String _s, byte[] msg)
  {
      BigInteger x = new BigInteger(_x);
      BigInteger y = new BigInteger(_y);
      BigInteger r = new BigInteger(_r);
      BigInteger s = new BigInteger(_s);

      /* TODO */

      return false;
  }

  public static String BignumCalc(String _bn1, String _bn2, String _bn3, int op)
  {
      BigInteger bn1 = new BigInteger(_bn1);
      BigInteger bn2 = new BigInteger(_bn2);
      BigInteger bn3 = new BigInteger(_bn3);

      BigInteger res = new BigInteger("0");

      if ( op == 0 ) {
          res = bn1.add(bn2);
      } else if ( op == 1 ) {
          res = bn1.subtract(bn2);
      } else if ( op == 2 ) {
          res = bn1.multiply(bn2);
      } else if ( op == 3 ) {
          res = bn1.divide(bn2);
      } else if ( op == 4 ) {
          res = bn1.gcd(bn2);
      } else if ( op == 5 ) {
          res = bn1.and(bn2);
      } else if ( op == 6 ) {
          res = bn1.or(bn2);
      } else if ( op == 7 ) {
          res = bn1.xor(bn2);
      } else if ( op == 8 ) {
          res = bn1.modInverse(bn2);
      } else if ( op == 9 ) {
          res = bn1.modPow(bn2, bn3);
      } else if ( op == 10 ) {
          res = bn1.abs();
      } else if ( op == 11 ) {
          res = bn1.negate();
      } else if ( op == 12 ) {
          res = bn1.mod(bn2);
      } else if ( op == 13 ) {
          res = bn1.pow(bn2.intValueExact());
      } else if ( op == 14 ) {
          res = bn1.min(bn2);
      } else if ( op == 15 ) {
          res = bn1.max(bn2);
      } else if ( op == 16 ) {
          res = bn1.sqrt();
      } else if ( op == 17 ) {
          res = bn1.shiftLeft(1);
      } else if ( op == 18 ) {
          res = bn1.shiftRight(bn2.intValueExact());
      } else if ( op == 19 ) {
          res = bn1.testBit(bn2.intValueExact()) ? BigInteger.ONE : BigInteger.ZERO;
      } else if ( op == 20 ) {
          res = bn1.clearBit(bn2.intValueExact());
      } else if ( op == 21 ) {
          res = bn1.setBit(bn2.intValueExact());
      } else if ( op == 22 ) {
          res = new BigInteger(String.valueOf(bn1.bitLength()));
      } else if ( op == 23 ) {
          res = new BigInteger(String.valueOf(bn1.compareTo(bn2)));
      } else if ( op == 24 ) {
          res = bn1.multiply(bn1);
      } else {
          return "none";
      }

     return res.toString();
  }
}
