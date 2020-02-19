# Building zkgroup for Swift / iOS
This document describes how to build and package zkgroup for Swift. We assume the repository is already available (i.e. cloned with git).

## tl;dr
```
$ make
```

Always test:
- Open the ZKGroup.xcodeproj
- Choose the Test scheme to run tests

## From Zero

### Mac
Ensure that Xcode and Rust are installed.

- Install Rust from: https://www.rust-lang.org/tools/install
- Install the cargo-lipo and cbindgen utilities
- Install all the required toolchains

Example:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install cbindgen
cargo install cargo-lipo

rustup target add aarch64-apple-ios x86_64-apple-ios armv7-apple-ios armv7s-apple-ios
```

`rustup show` should indicate that the `x86_64-apple-darwin` is the host and stable, as well as having all the targets above listed.

## Building
Only build using a Mac. From this directory, run make:
```
make
```
This will result in a universal library containing all the targets and header file which are copied to the ZKGroup/libzkgroup directory.

To ensure proper operation, it is suggested to open the ZKGroup.xcodeproj and run tests from there.

## Packaging
When either the source code or binaries have been updated, the entire swift directory and associated binary artifacts can be used to create a new artifact repository branch.

There is a script that can help with the copying bit. For example, to copy to the `signal-zkgroup-swift` repository that is at the same directory level as `zkgroup`:
```
Scripts/copy_repo.sh . ../../../signal-zkgroup-swift
```

Now a branch can be created in signal-zkgroup-swift and pushed to the upstream remote to serve as the formal release.
