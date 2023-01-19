using System;
using System.IO;
using System.Text.Json;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Asn1.Sec;



namespace Cryptofuzz
{
    class Program
    {
        static BigInteger loadBn(string bn)
        {
            if (bn == "-") {
                bn = "-0";
            } else if ( bn == "" ) {
                bn = "0";
            }
            return new BigInteger(bn, 10);
        }

        static void assert(bool cond)
        {
            if (!cond) {
                throw new Exception("Assert failed");
            }
        }

        static void ECC_Point_Add(
                BigInteger a_x, BigInteger a_y,
                BigInteger b_x, BigInteger b_y,
                BigInteger r_x, BigInteger r_y,
                string curveName) {
            var curve = CustomNamedCurves.GetByName(curveName);
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            var a = curve.Curve.CreatePoint(a_x, a_y);
            var b = curve.Curve.CreatePoint(b_x, b_y);
            var r = a.Add(b);
            r = r.Normalize();

            if ( a.IsValid() && b.IsValid() ) {
                if ( !r.XCoord.ToBigInteger().Equals(r_x) ||
                     !r.YCoord.ToBigInteger().Equals(r_y)) {
                    Console.WriteLine("ECC_Point_Add:");
                    Console.WriteLine("A_X: {0}", a_x.ToString());
                    Console.WriteLine("A_Y: {0}", a_y.ToString());
                    Console.WriteLine("B_X: {0}", b_x.ToString());
                    Console.WriteLine("B_Y: {0}", b_y.ToString());

                    Console.WriteLine("Expected:");
                    Console.WriteLine("X: {0}", r_x.ToString());
                    Console.WriteLine("Y: {0}", r_y.ToString());
                    Console.WriteLine("Got:");
                    Console.WriteLine("X: {0}", r.XCoord.ToBigInteger().ToString());
                    Console.WriteLine("Y: {0}", r.YCoord.ToBigInteger().ToString());
                    assert(false);
                }
            }
        }

        static void ECC_Point_Mul(
                BigInteger a_x, BigInteger a_y,
                BigInteger b,
                BigInteger r_x, BigInteger r_y,
                string curveName) {
            var curve = CustomNamedCurves.GetByName(curveName);
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            var a = curve.Curve.CreatePoint(a_x, a_y);
            var r = a.Multiply(b);
            r = r.Normalize();

            if ( a.IsValid() ) {
                if ( !r.XCoord.ToBigInteger().Equals(r_x) ||
                     !r.YCoord.ToBigInteger().Equals(r_y)) {
                    Console.WriteLine("ECC_Point_Add:");
                    Console.WriteLine("A_X: {0}", a_x.ToString());
                    Console.WriteLine("A_Y: {0}", a_y.ToString());
                    Console.WriteLine("B: {0}", b.ToString());

                    Console.WriteLine("Expected:");
                    Console.WriteLine("X: {0}", r_x.ToString());
                    Console.WriteLine("Y: {0}", r_y.ToString());
                    Console.WriteLine("Got:");
                    Console.WriteLine("X: {0}", r.XCoord.ToBigInteger().ToString());
                    Console.WriteLine("Y: {0}", r.YCoord.ToBigInteger().ToString());
                    assert(false);
                }
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Error: No file specified.");
                return;
            }

            var lines = File.ReadLines(args[0]);

            foreach (var line in lines)
            {
                JsonElement json = JsonSerializer.Deserialize<JsonElement>(line);
                JsonElement operation = json.GetProperty("operation");
                switch ( operation.GetProperty("operation").GetString() ) {
                    case    "BignumCalc":
                        BigInteger bn0 = loadBn(operation.GetProperty("bn0").GetString());
                        BigInteger bn1 = loadBn(operation.GetProperty("bn1").GetString());
                        BigInteger bn2  = loadBn(operation.GetProperty("bn2").GetString());
                        BigInteger result = loadBn(json.GetProperty("result").GetString());

                        switch ( operation.GetProperty("calcOp").GetString() ) {
                            case    "10633833424446033180":
                                assert(bn0.Add(bn1).Equals(result));
                                break;
                            case "7565474059520578463":
                                assert(bn0.Subtract(bn1).Equals(result));
                                break;
                            case "12211643382727132651":
                                assert(bn0.Multiply(bn1).Equals(result));
                                break;
                            case "13646095757308424912":
                                assert(bn0.Divide(bn1).Equals(result));
                                break;
                            case "12110391648600810285":
                                assert(bn0.Mod(bn1).Equals(result));
                                break;
                            case "1317996975705594123":
                                assert(bn0.ModPow(bn1, bn2).Equals(result));
                                break;
                            case "5785484340816638963":
                                assert(bn0.Gcd(bn1).Equals(result));
                                break;
                            case "1431659550035644982":
                                assert(bn0.And(bn1).Equals(result));
                                break;
                            case "2652194927012011212":
                                assert(bn0.Or(bn1).Equals(result));
                                break;
                            case "14328566578340454326":
                                assert(bn0.Xor(bn1).Equals(result));
                                break;
                            case "497803678004747625":
                                assert(bn0.Negate().Equals(result));
                                break;
                            case "8313790271709138543":
                                assert(bn0.Abs().Equals(result));
                                break;
                            case "1135892590552068761":
                                assert(bn0.Min(bn1).Equals(result));
                                break;
                            case "2316310815682592019":
                                assert(bn0.Max(bn1).Equals(result));
                                break;
                            case "4944816444068270084":
                                try {
                                    assert(bn0.ModInverse(bn1).Equals(result));
                                } catch ( System.ArithmeticException ) {
                                    assert(BigInteger.Zero.Equals(result));
                                }
                                break;
                            default:
                                break;
                        }

                        break;
                    case    "ECC_Point_Add":
                        {
                            BigInteger a_x = loadBn(operation.GetProperty("a_x").GetString());
                            BigInteger a_y = loadBn(operation.GetProperty("a_y").GetString());
                            BigInteger b_x = loadBn(operation.GetProperty("b_x").GetString());
                            BigInteger b_y = loadBn(operation.GetProperty("b_y").GetString());
                            BigInteger r_x = loadBn(json.GetProperty("result")[0].GetString());
                            BigInteger r_y = loadBn(json.GetProperty("result")[1].GetString());

                            switch ( operation.GetProperty("curveType").GetString() ) {
                                case    "18415819059127753777":
                                    ECC_Point_Add(a_x, a_y, b_x, b_y, r_x, r_y, "secp256r1");
                                    break;
                                case    "18393850816800450172":
                                    ECC_Point_Add(a_x, a_y, b_x, b_y, r_x, r_y, "secp256k1");
                                    break;
                                default:
                                    break;
                            }
                            break;
                        }
                    case    "ECC_Point_Mul":
                        {
                            BigInteger a_x = loadBn(operation.GetProperty("a_x").GetString());
                            BigInteger a_y = loadBn(operation.GetProperty("a_y").GetString());
                            BigInteger b = loadBn(operation.GetProperty("b").GetString());
                            BigInteger r_x = loadBn(json.GetProperty("result")[0].GetString());
                            BigInteger r_y = loadBn(json.GetProperty("result")[1].GetString());

                            switch ( operation.GetProperty("curveType").GetString() ) {
                                case    "18415819059127753777":
                                    ECC_Point_Mul(a_x, a_y, b, r_x, r_y, "secp256r1");
                                    break;
                                case    "18393850816800450172":
                                    ECC_Point_Mul(a_x, a_y, b, r_x, r_y, "secp256k1");
                                    break;
                                default:
                                    break;
                            }
                            break;
                        }
                    default:
                        break;
                }
            }
        }
    }
}
