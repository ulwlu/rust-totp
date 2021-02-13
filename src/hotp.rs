use hmac::{Hmac, Mac, NewMac};
use hmacsha1::hmac_sha1;
use sha2::{Sha256, Sha512};

pub enum HashType {
    Sha1,
    Sha256,
    Sha512,
}

enum HashReceiver {
    Sha1([u8; 20]),
    Sha256(Box<Hmac<Sha256>>),
    Sha512(Box<Hmac<Sha512>>),
}

pub fn generate_otp(secret: &[u8], counter: &[u8], digits: u32, digest: HashType) -> u64 {
    let hasher = generate_hasher(secret, counter, digest);
    truncate_hasher(&hasher, digits)
}

fn generate_hasher(secret: &[u8], counter: &[u8], digest: HashType) -> Vec<u8> {
    let hmac = match digest {
        HashType::Sha1 => HashReceiver::Sha1(hmac_sha1(secret, counter)),
        HashType::Sha256 => HashReceiver::Sha256(Box::new(
            Hmac::<Sha256>::new_varkey(secret).expect("HMAC is able to accept all key sizes"),
        )),
        HashType::Sha512 => HashReceiver::Sha512(Box::new(
            Hmac::<Sha512>::new_varkey(secret).expect("HMAC is able to accept all key sizes"),
        )),
    };

    // hasher is surely 20 byte sized, but hmac lib returns unsized.
    match hmac {
        HashReceiver::Sha1(hmac) => hmac.to_vec(),
        HashReceiver::Sha256(mut hmac) => {
            hmac.update(counter);
            hmac.finalize().into_bytes().to_vec()
        }
        HashReceiver::Sha512(mut hmac) => {
            hmac.update(counter);
            hmac.finalize().into_bytes().to_vec()
        }
    }
}

fn truncate_hasher(hasher: &[u8], digits: u32) -> u64 {
    // offset_bit is the decimal number of the last 4 bits of hasher.
    let offset_bit = (hasher[hasher.len() - 1] & 0xf) as usize;
    let mut hasher_partial_value = 0u64;
    // ex.) hasher_partial_value
    // if offset = 10, and
    // hasher[10] = 0x99, hasher[11] = 0x88, hasher[12] = 0x77, hasher[13] = 0x66,
    // you want to get the decimal number of 0x99887766.
    hasher_partial_value += (hasher[offset_bit] as u64) << (24 as u64);
    hasher_partial_value += (hasher[offset_bit + 1] as u64) << (16 as u64);
    hasher_partial_value += (hasher[offset_bit + 2] as u64) << (8 as u64);
    hasher_partial_value += hasher[offset_bit + 3] as u64;
    // otp is the decimal number of the last 32bits of hasher_partial_value.
    let otp = hasher_partial_value & 0x7fffffff;

    otp % 10_u64.pow(digits)
}

#[test]
fn test_generate_otp() {
    // test values from RFC 4226
    // https://tools.ietf.org/html/rfc4226#page-32
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 0],
            6,
            HashType::Sha1
        ),
        755224
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 1],
            6,
            HashType::Sha1
        ),
        287082
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 2],
            6,
            HashType::Sha1
        ),
        359152
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 3],
            6,
            HashType::Sha1
        ),
        969429
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 4],
            6,
            HashType::Sha1
        ),
        338314
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 5],
            6,
            HashType::Sha1
        ),
        254676
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 6],
            6,
            HashType::Sha1
        ),
        287922
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 7],
            6,
            HashType::Sha1
        ),
        162583
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 8],
            6,
            HashType::Sha1
        ),
        399871
    );
    assert_eq!(
        generate_otp(
            b"12345678901234567890",
            &[0, 0, 0, 0, 0, 0, 0, 9],
            6,
            HashType::Sha1
        ),
        520489
    );
}
