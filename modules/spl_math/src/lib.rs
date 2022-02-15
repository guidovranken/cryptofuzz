use spl_math::precise_number::PreciseNumber;

#[no_mangle]
pub extern "C" fn spl_math_sqrt(v1: u64, v2: u64) -> u64 {
    let v = ((v2 as u128) << 64) + (v1 as u128);
    let pn = PreciseNumber::new(v).unwrap();
    return pn.sqrt().unwrap().to_imprecise().unwrap() as u64;
}
