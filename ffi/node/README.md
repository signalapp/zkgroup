# Overview

First install Rust via rustup and switch to nightly:

https://www.rust-lang.org/tools/install

    rustup toolchain install nightly
    rustup default nightly

Then build the `.so` file with `cargo build --release`. Set environment variable `LD_LIBRARY_PATH` to `[projectdir]/target/release/`, which should contain `libzkgroup.so`.

First make sure you're on the proper version of Node, currently 12.4.0. `nvm` is a useful tool; the project has an `.nvmrc` file to make it easy to use the proper version.

Then install dependencies with `npm install`, and `npm run build` and `npm test` to build and test the Typescript.
