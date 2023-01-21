import std.json;
import std.stdio;
import std.file;
import std.bigint;

BigInt loadBn(string bn) {
    if ( bn == "" ) {
        return BigInt("0");
    } else {
        return BigInt(bn);
    }
}

void main(string[] argv) {
    File file = File(argv[1], "r");
    foreach (line; file.byLine) {
        auto j = parseJSON(line);
        auto op = j["operation"];
        if ( op["operation"].get!string == "BignumCalc" ) {
            auto bn0 = loadBn(op["bn0"].get!string);
            auto bn1 = loadBn(op["bn1"].get!string);
            auto bn2 = loadBn(op["bn2"].get!string);
            auto result = loadBn(j["result"].get!string);

            switch ( op["calcOp"].get!string ) {
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
                    if (bn1 != BigInt(0) ) {
                        assert(powmod(bn0, bn1, bn2) == result);
                    }
                    break;
                case "2652194927012011212":
                    assert((bn0 | bn1) == result);
                    break;
                case "1431659550035644982":
                    assert((bn0 & bn1) == result);
                    break;
                case "14328566578340454326":
                    assert((bn0 ^ bn1) == result);
                    break;
                default:
                    break;
            }
        }
    }
}
