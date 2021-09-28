
.PHONY: native_library
.PHONY: jar
.PHONY: test

native_library:
	cargo build --release
	cp ../../target/release/libzkgroup.so src/main/resources/ 2>/dev/null || \
		cp ../../target/release/libzkgroup.dylib src/main/resources/

jar:
	mvn package

test:
	mvn test

