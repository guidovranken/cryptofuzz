using System;
using System.IO;
using System.Numerics;
using System.Diagnostics;
using System.Text.Json;
using System.Security.Cryptography;

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
            return BigInteger.Parse(bn);
        }

        static void assert(bool cond)
        {
            if (!cond) {
                throw new Exception("Assert failed");
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
                                assert(bn0 + bn1 == result);
                                break;
                            case "7565474059520578463":
                                assert(bn0 - bn1 == result);
                                break;
                            case "12211643382727132651":
                                assert(bn0 * bn1 == result);
                                break;
                            case "13646095757308424912":
                                assert(bn0 / bn1 == result);
                                break;
                            case "12110391648600810285":
                                assert(bn0 % bn1 == result);
                                break;
                            case "1317996975705594123":
                                assert(BigInteger.ModPow(bn0, bn1, bn2) == result);
                                break;
                            case "5785484340816638963":
                                assert(BigInteger.GreatestCommonDivisor(bn0, bn1) == result);
                                break;
                            default:
                                break;
                        }

                        break;
                    default:
                        break;
                }
            }
        }
    }
}
