
# Overview

This library provides zero-knowledge group functionality through several layers of APIs.  From lower-level to higher-level:

 * `internal.rs` provides the actual Rust implementations, based on Rust structures.

 * `simpleapi.rs` provides wrapper functions around internal.rs functions that use `serde` to serialize/deseralize byte arrays into Rust structures.

 * `ffiapi.rs` and `ffiapijava.rs` provide wrapper functions around `simpleapi.rs` functions to export them via C and JNI, respectively.

 * The subdirectories under `ffi` contain code in various host languages for accessing the exported functions:  

     * Under `c` is a `zkgroup.h` header file.

     * Under `android` is a `ZKGroup.java` file and instructions for building an aar.

     * Under `node` is some example code for declaring the FFI functions in javascript.

Setup
==

Set to `stable` toolchain.

```
rustup default stable
```

Install [rustup](https://rustup.rs/) and these targets:

```
rustup target add armv7-linux-androideabi   # for arm
rustup target add i686-linux-android        # for x86
rustup target add aarch64-linux-android     # for arm64
rustup target add x86_64-linux-android      # for x86_64
rustup target add x86_64-unknown-linux-gnu  # for linux-x86-64
rustup target add x86_64-apple-darwin       # for macOS (darwin)
```

Building Rust
==

Run `./gradlew tasks` and see `make` tasks under the "Rust tasks" group.
