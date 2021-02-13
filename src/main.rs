mod hotp;
mod totp;

use hotp::HashType;
use structopt::clap::AppSettings::{ColorAlways, ColoredHelp};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "rust-totp",
    about = "Implementation of totp in Rust",
    setting(ColorAlways),
    setting(ColoredHelp),
    after_help = "This is just for personal use."
)]
struct Opt {
    #[structopt(long = "secret")]
    pub secret: String,

    #[structopt(long = "timestep", default_value = "30")]
    pub time_step: u64,

    #[structopt(long = "offset", default_value = "0")]
    pub time_offset: u64,

    #[structopt(long = "digits", default_value = "6")]
    pub digits: u32,

    #[structopt(long = "digest", default_value = "512")]
    pub digest: u64,
}

fn main() {
    let opt = Opt::from_args();
    let secret = &opt.secret.as_bytes();
    let time_step = opt.time_step;
    let time_offset = opt.time_offset;
    let digits = opt.digits;
    // clap's arg_enum and
    // structopt's possible_values also works this limitation.
    let digest = match opt.digest {
        1 => HashType::Sha1,
        256 => HashType::Sha256,
        512 => HashType::Sha512,
        _ => panic!("Use 1/256/512 only for digest."),
    };

    let otp = totp::generate_otp(secret, time_step, time_offset, digits, digest);
    println!("{}", otp);
}
