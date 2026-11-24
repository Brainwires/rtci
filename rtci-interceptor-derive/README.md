# rtci-interceptor-derive

Procedural macros for `rtci-interceptor`: `#[derive(Interceptor)]` marks a struct as an
interceptor and names the field holding the next one in the chain, and the `#[interceptor]`
attribute on an `impl` block generates the trait implementation, forwarding every method the
block does not define to that field.

## Use

Depend on `rtci-interceptor`, which re-exports the macros; a crate that defines its own
interceptors needs this crate only through it. The macros' documentation, and the
interceptors in `rtci-interceptor`'s sources, show the pattern.

The macros generate code only; they implement no protocol, and the generated code does no
I/O.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
