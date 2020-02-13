.PHONY: android_so
.PHONY: server_so
.PHONY: mac_dylib

android_so:
	cargo build --target aarch64-linux-android --release
	cargo build --target armv7-linux-androideabi --release
	cargo build --target i686-linux-android --release
	cargo build --target x86_64-linux-android --release
	cp target/armv7-linux-androideabi/release/libzkgroup.so \
		android/lib/src/main/jniLibs/armeabi-v7a/
	cp target/aarch64-linux-android/release/libzkgroup.so \
		android/lib/src/main/jniLibs/arm64-v8a/
	cp target/i686-linux-android/release/libzkgroup.so \
		android/lib/src/main/jniLibs/x86/
	cp target/x86_64-linux-android/release/libzkgroup.so \
		android/lib/src/main/jniLibs/x86_64/

server_so:
	cargo build --target x86_64-unknown-linux-gnu --release
	mkdir -p java/src/main/resources/ 
	cp target/x86_64-unknown-linux-gnu/release/libzkgroup.so java/src/main/resources/

mac_dylib:
	cargo build --target x86_64-apple-darwin --release
	mkdir -p java/src/main/resources/ 
	cp target/x86_64-apple-darwin/release/libzkgroup.dylib java/src/main/resources/
