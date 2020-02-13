
# Overview

First setup your Rust toolchain for cross-compiling, per below.

Then use "make so" in this directory to build the .so libraries and copy them into this directory's Gradle project.

Then run "./gradlew :zkgroup:assemble" in this directory to build the aar file.


# Setting up the Rust toolchain for cross-compiling

https://medium.com/visly/rust-on-android-19f34a2fb43

https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html

First install Rust via rustup:

https://www.rust-lang.org/tools/install

Then add cross-compilation targets:

    rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

Then create linker "toolchains":

    $ANDROID_HOME/ndk-bundle/build/tools/make_standalone_toolchain.py --api 26 --arch arm64 --install-dir ~/.NDK/arm64

    $ANDROID_HOME/ndk-bundle/build/tools/make_standalone_toolchain.py --api 26 --arch arm --install-dir ~/.NDK/ar

    $ANDROID_HOME/ndk-bundle/build/tools/make_standalone_toolchain.py --api 26 --arch x86 --install-dir ~/.NDK/x86

    $ANDROID_HOME/ndk-bundle/build/tools/make_standalone_toolchain.py --api 26 --arch x86_64 --install-dir ~/.NDK/x86_64

Then add the following into ~/.cargo/config:
```
[target.aarch64-linux-android]
ar = ".NDK/arm64/bin/aarch64-linux-android-ar"
linker = ".NDK/arm64/bin/aarch64-linux-android-clang"

[target.armv7-linux-androideabi]
ar = ".NDK/arm/bin/arm-linux-androideabi-ar"
linker = ".NDK/arm/bin/arm-linux-androideabi-clang"

[target.i686-linux-android]
ar = ".NDK/x86/bin/i686-linux-android-ar"
linker = ".NDK/x86/bin/i686-linux-android-clang"

[target.x86_64-linux-android]
ar = ".NDK/x86_64/bin/x86_64-linux-android-ar"
linker = ".NDK/x86_64/bin/x86_64-linux-android-clang"
```

