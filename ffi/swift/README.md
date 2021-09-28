# Overview

This is a binding to the ZKGroup code in rust/, implemented on top of the C FFI produced by cbindgen. It's set up as a CocoaPod for integration into the Signal iOS client and as a Swift Package for local development.

# Use as CocoaPod

1. Make sure you are using `use_frameworks!` in your Podfile. ZKGroup is a Swift pod and as such cannot be compiled as a plain library.

2. Add 'ZKGroup' as a dependency in your Podfile:

        pod 'ZKGroup', git: 'https://github.com/signalapp/zkgroup.git'

3. Use `pod install` or `pod update` to build the Rust library for both iOS simulator and iOS device

4. Build as usual. The Rust library will automatically be linked into the built ZKGroup.framework.


## Development as a CocoaPod

Instead of a git-based dependency, use a path-based dependency to treat ZKGroup as a development pod. Since [`prepare_command`s][pc] are not run for path-based dependencies, you will need to build the Rust library yourself. (Xcode should prompt you to do this if you forget.)

    CARGO_BUILD_TARGET=x86_64-apple-ios ffi/swift/build_ffi.sh --release

The CocoaPod is configured to use the release build of the Rust library.

When exposing new APIs to Swift, you will need to add the `--generate-ffi` flag to your
`build_ffi.sh` invocation.

[pc]: https://guides.cocoapods.org/syntax/podspec.html#prepare_command
