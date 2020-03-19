# Building zkgroup for Android
This document describes how to build and package zkgroup for Android. We assume the repository is already available (i.e. cloned with git).

## tl;dr
```
$ ./gradlew build
```

## From Zero

### Linux (Ubuntu 18.04)
Install dependencies (if not already done) and Rust.

Example:
```
sudo apt update
sudo apt install build-essential wget curl git vim
sudo apt install python2.7 python-pip
sudo apt install openjdk-8-jdk

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

`rustup show` should indicate that the `x86_64-unknown-linux-gnu` is the host and stable, active toolchain.

#### Install Other Dependencies

##### Android Studio
This is recommended. Add the NDK, LLDB, Android SDK Tools, and any updates as needed. You may also need:
```
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 lib32z1 libbz2-1.0:i386
```

##### Android SDK & NDK
Set SDK and NDK locations (at the end of ~/.bashrc). For example:
```
export ANDROID_HOME=/home/signal/Android/Sdk
export NDK_HOME=/home/signal/Android/Sdk/ndk/21.0.6113669
export PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools
```

##### Android Rust Targets
```
rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android
```

##### Install Cargo NDK
```
cargo install cargo-ndk
```

## Building
From the project root directory, using gradle:
```
./gradlew build
```

This will build all Rust and Java dependencies, and setup the AAR file(s) necessary for testing.

## Packaging
TBD
