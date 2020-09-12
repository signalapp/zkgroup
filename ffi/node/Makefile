ZKGROUP_RUST_DIR=../../rust
ZKGROUP_TARGET_DIR=../../target

ifeq ($(OS),Windows_NT)
	DETECTED_OS := Windows
else
	DETECTED_OS := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
endif

ifeq ($(DETECTED_OS),Windows)
	SOURCE_LIB = zkgroup.dll
	TARGET_LIB = libzkgroup_x64.dll
	TARGET_LIB_x86 = libzkgroup_x86.dll
	TARGET_LIB_arm64 = libzkgroup_arm64.dll
	RUSTFLAGS = '-C link-arg=-s -C target-feature=+crt-static'
endif
ifeq ($(DETECTED_OS),Linux)
	SOURCE_LIB = libzkgroup.so
	TARGET_LIB = libzkgroup.so
	RUSTFLAGS='-C link-arg=-s'
endif
ifeq ($(DETECTED_OS),Darwin)
	SOURCE_LIB = libzkgroup.dylib
	TARGET_LIB = libzkgroup.dylib
	RUSTFLAGS='-C link-arg=-s'
endif

default: libzkgroup

clean:
	rm $(TARGET_LIB)
	rm -r node_modules

libzkgroup: FORCE
	RUSTFLAGS=$(RUSTFLAGS)

	cargo build --manifest-path=$(ZKGROUP_RUST_DIR)/Cargo.toml --release
	rm -f $(TARGET_LIB)
	mv $(ZKGROUP_TARGET_DIR)/release/$(SOURCE_LIB) $(TARGET_LIB)

ifeq ($(DETECTED_OS),Windows)
	cargo build --target i686-pc-windows-msvc --manifest-path=$(ZKGROUP_RUST_DIR)/Cargo.toml --release
	rm -f $(TARGET_LIB_x86)
	mv $(ZKGROUP_TARGET_DIR)/i686-pc-windows-msvc/release/$(SOURCE_LIB) $(TARGET_LIB_x86)

	cargo build --target aarch64-pc-windows-msvc --manifest-path=$(ZKGROUP_RUST_DIR)/Cargo.toml --release
	rm -f $(TARGET_LIB_arm64)
	mv $(ZKGROUP_TARGET_DIR)/aarch64-pc-windows-msvc/release/$(SOURCE_LIB) $(TARGET_LIB_arm64)
endif

test: FORCE
	npm install
	npm run build
	npm test

FORCE:
