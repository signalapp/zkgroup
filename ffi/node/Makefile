ZKGROUP_RUST_DIR=../../rust
ZKGROUP_TARGET_DIR=../../target

ifeq ($(OS),Windows_NT)
	detected_OS := Windows
else
	detected_OS := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
endif

ifeq ($(detected_OS),Windows)
	source_lib = zkgroup.dll
	target_lib = libzkgroup.dll
endif
ifeq ($(detected_OS),Linux)
	source_lib = libzkgroup.so
	target_lib = libzkgroup.so
endif
ifeq ($(detected_OS),Darwin)
	source_lib = libzkgroup.dylib
	target_lib = libzkgroup.dylib
endif

default: libzkgroup

clean:
	rm libzkgroup.dylib
	rm -r node_modules

libzkgroup: FORCE
	cargo build --manifest-path=$(ZKGROUP_RUST_DIR)/Cargo.toml --release
	rm -f $(target_lib)
	mv $(ZKGROUP_TARGET_DIR)/release/$(source_lib) $(target_lib)

test: FORCE
	npm install
	npm run build
	npm test

FORCE:
