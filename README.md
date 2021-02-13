# Rust-totp
Just personal implementation of TOTP in Rust.

https://tools.ietf.org/html/rfc6238
https://tools.ietf.org/html/rfc4226

## usage

```
# build
just build

# execute
# only secret is required option.
rust-totp --digest <digest> --digits <digits> --secret <secret> --offset <time-offset> --timestep <time-step>

# test
just test
```
