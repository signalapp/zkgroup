ZKGROUP_RUST_DIR=../../rust
ZKGROUP_TARGET_DIR=../../target

NODE_ARCH := $(shell node -p "process.arch" || echo x64)

ifeq ($(OS),Windows_NT)
	DETECTED_OS := Windows
else
	DETECTED_OS := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
endif

ifeq ($(DETECTED_OS),Windows)
	SOURCE_LIB = zkgroup.dll
	TARGET_LIB = libzkgroup-$(NODE_ARCH).dll
	RUSTFLAGS = '-C link-arg=-s -C target-feature=+crt-static'
endif
ifeq ($(DETECTED_OS),Linux)
	SOURCE_LIB = libzkgroup.so
	TARGET_LIB = libzkgroup-$(NODE_ARCH).so
	RUSTFLAGS='-C link-arg=-s'
endif
ifeq ($(DETECTED_OS),Darwin)
	SOURCE_LIB = libzkgroup.dylib
	TARGET_LIB = libzkgroup-$(NODE_ARCH).dylib
	RUSTFLAGS='-C link-arg=-s'
endif

default: libzkgroup

clean:
	rm $(TARGET_LIB)
	rm -r node_modules

.PHONY: libzkgroup
libzkgroup:
	RUSTFLAGS=$(RUSTFLAGS) cargo build --manifest-path=$(ZKGROUP_RUST_DIR)/Cargo.toml --release
	rm -f $(TARGET_LIB)
	mv $(ZKGROUP_TARGET_DIR)/${CARGO_BUILD_TARGET}/release/$(SOURCE_LIB) $(TARGET_LIB)

.PHONY: test
test:
	npm install
	npm run build
	npm test
