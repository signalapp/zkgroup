.PHONY: server_so
.PHONY: mac_dylib

server_so:
	cargo build --target x86_64-unknown-linux-gnu --release
	mkdir -p java/src/main/resources/ 
	cp target/x86_64-unknown-linux-gnu/release/libzkgroup.so java/src/main/resources/

mac_dylib:
	cargo build --target x86_64-apple-darwin --release
	mkdir -p java/src/main/resources/ 
	cp target/x86_64-apple-darwin/release/libzkgroup.dylib java/src/main/resources/
