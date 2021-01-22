# Botan module for Cryptofuzz

## Using Botan as an oracle

Botan is richly featured and as such is a good candidate to fuzz another library against.

If you use Botan for this purpose, define `CRYPTOFUZZ_BOTAN_IS_ORACLE` before compiling the module. This decreases the internal variance of its operations (which is good to find bugs in Botan itself) and makes it less likely for operations to fail.
