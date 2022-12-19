import java.util.Arrays;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class CryptofuzzJavaHarness
{
  public static byte[] Digest(String hash, byte[] msg, int[] chunks)
  {
      try {
          MessageDigest md = MessageDigest.getInstance(hash);
          int curpos = 0;
          for (int i = 0; i < chunks.length; i++) {
              int cursize = chunks[i];
              md.update(Arrays.copyOfRange(msg, curpos, curpos + cursize));
              curpos += cursize;
          }
          return md.digest();
      } catch ( java.security.NoSuchAlgorithmException e ) {
          return new byte[0];
      }
  }

  public static byte[] HMAC(String hash, byte[] key, byte[] msg, int[] chunks)
  {
      try {
          SecretKey keyKi = new SecretKeySpec(key, "HMAC");
          Mac m = Mac.getInstance("Hmac" + hash);
          m.init(keyKi);
          int curpos = 0;
          for (int i = 0; i < chunks.length; i++) {
              int cursize = chunks[i];
              m.update(Arrays.copyOfRange(msg, curpos, curpos + cursize));
              curpos += cursize;
          }
          return m.doFinal();
      } catch ( java.security.NoSuchAlgorithmException e ) {
          return new byte[0];
      } catch ( java.security.InvalidKeyException e ) {
          return new byte[0];
      }
  }

  public static boolean ECDSA_Verify(String hash, byte[] pub, byte[] sig, byte[] msg, int[] chunks)
  {
      try {
          EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pub);
          KeyFactory keyFactory = KeyFactory.getInstance("EC");
          PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

          Signature signature = Signature.getInstance(hash + "withECDSA");
          signature.initVerify(publicKey);
          int curpos = 0;
          for (int i = 0; i < chunks.length; i++) {
              int cursize = chunks[i];
              signature.update(Arrays.copyOfRange(msg, curpos, curpos + cursize));
              curpos += cursize;
          }
          return signature.verify(sig);
      } catch ( java.security.NoSuchAlgorithmException e ) {
          return false;
      } catch ( java.security.InvalidKeyException e ) {
          return false;
      } catch ( java.security.spec.InvalidKeySpecException e ) {
          return false;
      } catch ( SignatureException e ) {
          return false;
      }
  }

  public static byte[] PBKDF2(String hash, byte[] password, byte[] salt, int iterations, int keysize)
      throws NoSuchAlgorithmException, InvalidKeySpecException
  {
      char[] password2 = new char[password.length];
      for (int i = 0; i < password.length; i++) {
          password2[i] = (char)password[i];
      }
      PBEKeySpec spec = new PBEKeySpec(password2, salt, iterations, keysize);
      SecretKeyFactory skf = SecretKeyFactory.getInstance(hash);
      skf.generateSecret(spec).getEncoded();
      return skf.generateSecret(spec).getEncoded();
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
          try {
              res = bn1.modInverse(bn2);
          } catch ( ArithmeticException e ) {
              /* res remains 0 */
          }
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
