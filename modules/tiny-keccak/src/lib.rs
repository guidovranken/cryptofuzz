use tiny_keccak::{Hasher, Keccak};
use std::slice;
use std::ptr;

fn create_parts(
    input_bytes: *const u8, input_size: libc::size_t,
    parts_bytes: *const libc::size_t, parts_size: libc::size_t) -> Vec<Vec<u8>> {
    let input = unsafe { slice::from_raw_parts(input_bytes, input_size) };
    let parts = unsafe { slice::from_raw_parts(parts_bytes, parts_size) };
    let mut ret : Vec<Vec<u8>> = Vec::new();

    let mut pos = 0;
    for part in parts.iter() {
        ret.push(input[pos..(pos + *part)].to_vec());
        pos += part;
    }

    return ret;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_tiny_keccak(
    input_bytes: *const u8, input_size: libc::size_t,
    parts_bytes: *const libc::size_t, parts_size: libc::size_t,
    out: *mut u8) {
    let parts = create_parts(input_bytes, input_size, parts_bytes, parts_size);
    let mut hasher = Keccak::v256();

    for part in parts.iter() {
        hasher.update(part);
    }

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    unsafe {
        ptr::copy_nonoverlapping(output.as_ptr(), out, output.len());
    }
}
