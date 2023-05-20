use std::slice;
use std::ptr;
use aurora_engine_modexp::modexp;

#[no_mangle]
pub extern "C" fn cryptofuzz_aurora_engine_modexp(
            base_bytes: *mut u8, base_size: u64,
            exp_bytes: *mut u8, exp_size: u64,
            mod_bytes: *mut u8, mod_size: u64,
            result: *mut u8) {
    let base = unsafe { slice::from_raw_parts(base_bytes, base_size as usize) };
    let exp = unsafe { slice::from_raw_parts(exp_bytes, exp_size as usize) };
    let modulus = unsafe { slice::from_raw_parts(mod_bytes, mod_size as usize) };

    let mut r = modexp(base, exp, modulus);

    if r.len() > 4000 {
        panic!("Result too large");
    }
    r.reverse();

    unsafe {
        ptr::copy_nonoverlapping(r.as_ptr(), result, r.len());
    }
}
