# isideload-apple-platform-rs

This is a collection of rust crates for apple-codesign as used in isideload. Several other dependencies are also here, as they were patched for wasm support.

This repository contains a collection of Rust crates to support Apple
platforms.

See the various project directories for more.

The most notable project is `apple-codesign`, which contains a pure Rust
(re)implementation of Apple code signing and notarization. This enables
you to sign, notarize, and release Apple software without macOS and without
Apple hardware.
