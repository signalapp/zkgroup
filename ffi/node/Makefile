ZKGROUP_RUST_DIR=../../rust
ZKGROUP_TARGET_DIR=../../target

ifeq ($(OS),Windows_NT)
	DETECTED_OS := Windows
else
	DETECTED_OS := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
endif

ifeq ($(DETECTED_OS),Windows)
	SOURCE_LIB = zkgroup.dll
	TARGET_LIB = libzkgroup.dll
endif
ifeq ($(DETECTED_OS),Linux)
	SOURCE_LIB = libzkgroup.so
	TARGET_LIB = libzkgroup.so
endif
ifeq ($(DETECTED_OS),Darwin)
	SOURCE_LIB = libzkgroup.dylib
	TARGET_LIB = libzkgroup.dylib
endif

default: libzkgroup

clean:
	rm $(TARGET_LIB)
	rm -r node_modules

libzkgroup: FORCE
	RUSTFLAGS='-C link-arg=-s' cargo build --manifest-path=$(ZKGROUP_RUST_DIR)/Cargo.toml --release
	rm -f $(TARGET_LIB)
	mv $(ZKGROUP_TARGET_DIR)/release/$(SOURCE_LIB) $(TARGET_LIB)

test: FORCE
	npm install
	npm run build
	npm test

FORCE:
