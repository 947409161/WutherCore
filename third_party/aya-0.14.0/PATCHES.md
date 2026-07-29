# Aya 0.14.0 Android patch

Source: `aya` 0.14.0 from crates.io.

The only semantic changes are two `setsockopt` length arguments in
`src/sys/netlink.rs`. Upstream casts those lengths to `u32`, while 32-bit
Android bionic defines `socklen_t` as `i32`. This copy casts through
`libc::socklen_t`, which preserves the original type on Linux and makes Aya
compile for `armv7-linux-androideabi`. A few trailing spaces inherited from
the published crate were also removed to satisfy repository checks.

Remove this patch when an Aya release uses the platform `socklen_t` type.
