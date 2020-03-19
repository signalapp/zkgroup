ZKGROUP_RUST_DIR=../../rust
ZKGROUP_TARGET_DIR=../../target

default: zkgroup.h libzkgroup_ios.a

clean:
	rm ZKGroup/libzkgroup/zkgroup.h ZKGroup/libzkgroup/libzkgroup_ios.a

zkgroup.h: FORCE
	cbindgen --lang c $(ZKGROUP_RUST_DIR) -o ZKGroup/libzkgroup/zkgroup.h

libzkgroup_ios.a: FORCE
	cargo lipo --manifest-path=$(ZKGROUP_RUST_DIR)/Cargo.toml --release --targets=aarch64-apple-ios,x86_64-apple-ios,armv7-apple-ios,armv7s-apple-ios
	mv $(ZKGROUP_TARGET_DIR)/universal/release/libzkgroup.a ZKGroup/libzkgroup/libzkgroup_ios.a

install_build_dependencies:
	cargo install --version 0.9.0 cbindgen
	cargo install --version 3.0.1 cargo-lipo

FORCE:
