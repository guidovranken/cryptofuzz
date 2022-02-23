const io = @import("std").io;
const std = @import("std");
const Limb = std.math.big.Limb;
const mem = std.mem;
const hkdf = std.crypto.kdf.hkdf;

export fn cryptofuzz_zig_hkdf(
        res_data: [*:0]u8, res_size: u32,
        password_data: [*:0]const u8, password_size: u32,
        salt_data: [*:0]const u8, salt_size: u32,
        info_data: [*:0]const u8, info_size: u32,
        digest: u32) callconv(.C) void {
    if ( digest == 0 ) {
        const prk = hkdf.HkdfSha256.extract(
                salt_data[0..salt_size],
                password_data[0..password_size]);
        hkdf.HkdfSha256.expand(
                res_data[0..res_size],
                info_data[0..info_size],
                prk);
    } else if ( digest == 2 ) {
        const prk = hkdf.HkdfSha512.extract(
                salt_data[0..salt_size],
                password_data[0..password_size]);
        hkdf.HkdfSha512.expand(
                res_data[0..res_size],
                info_data[0..info_size],
                prk);
    } else {
        unreachable;
    }
}

export fn cryptofuzz_zig_bignumcalc(
        res_data: [*:0]u8, res_size: u32,
        a_data: [*:0]const u8, a_size: u32,
        b_data: [*:0]const u8, b_size: u32,
        op: u64,
        ) callconv(.C) i32 {
    const allocator = std.heap.page_allocator;

    var a = std.math.big.int.Managed.initSet(allocator, @as(usize, 1)) catch unreachable;
    defer a.deinit();

    var b = std.math.big.int.Managed.initSet(allocator, @as(usize, 1)) catch unreachable;
    defer b.deinit();

    var res = std.math.big.int.Managed.initSet(allocator, @as(usize, 1)) catch unreachable;
    defer res.deinit();

    a.setString(10, a_data[0..a_size]) catch unreachable;
    b.setString(10, b_data[0..b_size]) catch unreachable;

    if ( op == 0 ) {
        res.add(a.toConst(), b.toConst()) catch unreachable;
    } else if ( op == 1 ) {
        res.sub(a.toConst(), b.toConst()) catch unreachable;
    } else if ( op == 2 ) {
        res.mul(a.toConst(), b.toConst()) catch unreachable;
    } else if ( op == 3 ) {
        if ( !a.toConst().positive ) {
            return 1;
        }
        if ( !b.toConst().positive ) {
            return 1;
        }
        if ( b.toConst().eqZero() ) {
            return 1;
        }

        var mod = std.math.big.int.Managed.initSet(allocator, @as(usize, 1)) catch unreachable;
        defer mod.deinit();

        res.divFloor(&mod, a.toConst(), b.toConst()) catch unreachable;
    } else if ( op == 4 ) {
        if ( !a.toConst().positive ) {
            return 1;
        }
        if ( !b.toConst().positive ) {
            return 1;
        }
        if ( a.toConst().eqZero() ) {
            return 1;
        }
        if ( b.toConst().eqZero() ) {
            return 1;
        }
        //res.gcd(a, b) catch unreachable;
        res.gcd(a, b) catch {
            return 1;
        };
    } else if ( op == 5) {
        res.sqr(a.toConst()) catch unreachable;
    } else if ( op == 6 ) {
        if ( !a.toConst().positive ) {
            return 1;
        }
        if ( !b.toConst().positive ) {
            return 1;
        }
        if ( b.toConst().eqZero() ) {
            return 1;
        }

        var mod = std.math.big.int.Managed.initSet(allocator, @as(usize, 1)) catch unreachable;
        defer mod.deinit();

        res.divFloor(&mod, a.toConst(), b.toConst()) catch unreachable;
        res.swap(&mod);
    } else if ( op == 7 ) {
        res.shiftLeft(a, 1) catch unreachable;
    } else if ( op == 8 ) {
        res.bitAnd(a, b) catch unreachable;
    } else if ( op == 9 ) {
        res.bitOr(a, b) catch unreachable;
    } else if ( op == 10 ) {
        res.bitXor(a, b) catch unreachable;
    } else if ( op == 11 ) {
        res.copy(a.toConst().negate()) catch unreachable;
    } else if ( op == 12 ) {
        res.copy(a.toConst().abs()) catch unreachable;
    } else if ( op == 13 ) {
        res.set(a.toConst().bitCountAbs()) catch unreachable;
    } else if ( op == 14 ) {
        var count = b.toConst().to(usize) catch {
            return 1;
        };
        res.shiftRight(a, count) catch unreachable;
    } else if ( op == 15 ) {
        var power = b.toConst().to(u32) catch {
            return 1;
        };
        res.pow(a.toConst(), power) catch unreachable;
    } else {
        return 1;
    }

    var s = res.toString(allocator, 10, .lower) catch unreachable;
    mem.copy(u8, res_data[0..res_size], s);
    allocator.free(s);

    return 0;
}
