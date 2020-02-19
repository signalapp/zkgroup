# Building zkgroup for Node.js
This document describes how to build and package zkgroup for Node.js, to be used in an Electron application. We assume the repository is already available on each platform (i.e. cloned with git).

## tl;dr
```
$ make
```

Always test:
```
$ make test
```

## From Zero

### Node.js
Make sure you're on the proper version of Node, currently 12.4.0. `nvm` is a useful tool; the project has an `.nvmrc` file to make it easy.

For Mac and Linux, install Node as per: https://github.com/nvm-sh/nvm
```
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.2/install.sh | bash
nvm install 12.4.0
cd ffi/node
nvm use
```
For Windows, install Node as per: https://github.com/coreybutler/nvm-windows
```
nvm install 12.4.0
nvm use 12.4.0
```

### Linux (Ubuntu 18.04)
Install dependencies (if not already done) and Rust.

Example:
```
sudo apt install build-essential python2.7 python-pip curl

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

`rustup show` should indicate that the `x86_64-unknown-linux-gnu` is the host and stable, active toolchain.

### Mac
Install Rust.

Example:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

`rustup show` should indicate that the `x86_64-apple-darwin` is the host and stable, active toolchain.

### Windows
Install Windows Build Tools and Rust. For Rust, go to https://www.rust-lang.org/tools/install and follow the instructions for Windows.

It is recommended to run the installation using PowerShell, including the Windows Build Tools as an administrator.

Example:
```
npm install --global --production --add-python-to-path windows-build-tools --vs2015
```

`rustup show` should indicate that the `x86_64-pc-windows-msvc` is the host and stable, active toolchain.

If it doesn't, do the following:
```
rustup target add x86_64-pc-windows-msvc
rustup set default-host x86_64-pc-windows-msvc
rustup toolchain install stable
```

## Building
From this directory, run make:
```
make
```

This will build a release binary for the platform you are on. Repeat this for all platforms (Mac, Linux, Windows).

This will result in different library files for each of the target platforms:
- Linux: target/x86_64-unknown-linux-gnu/release/libzkgroup.so
- Mac: target/x86_64-apple-darwin/release/libzkgroup.dylib
- Windows: target/x86_64-pc-windows-msvc/release/zkgroup.dll

*In the case of Windows, you must rename `zkgroup.dll` to `libzkgroup.dll`.*

Next, test the build, which has the side effect of building the TypeScript as well:
```
make test
```

If all tests pass, go to the packaging step.

You can manually build the library by going to the project root and running a cargo command. For example, to build a debug library:
```
cargo build
```

## Packaging
When either the source code or binaries have been updated, the entire node directory and associated binary artifacts can be used to create a new artifact repository branch.

It is suggested that a platform be chosen as the reference, and copy over all the libraries that were built for the other platforms so they are all packaged together.

There is a script that can help with the copying bit. For example, to copy to the `signal-zkgroup-node` repository that is at the same directory level as `zkgroup`:
```
scripts/copy_repo.sh . ../../../signal-zkgroup-node
```

Now a branch can be created in signal-zkgroup-node and pushed to the upstream remote to serve as the formal release.
