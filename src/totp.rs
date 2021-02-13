use crate::hotp;
use byteorder::{BigEndian, ByteOrder};
use hotp::HashType;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_otp(
    secret: &[u8],
    time_step: u64,
    time_offset: u64,
    digits: u32,
    digest: HashType,
) -> u64 {
    let counter = generate_counter(time_step, time_offset);
    hotp::generate_otp(secret, &counter, digits, digest)
}

fn generate_counter(time_step: u64, time_offset: u64) -> [u8; 8] {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let counter = (current_time - time_offset) / time_step;
    let mut unpacked_counter = [0; 8];
    BigEndian::write_u64(&mut unpacked_counter, counter);

    unpacked_counter
}
