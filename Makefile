.PHONY: android_so
.PHONY: server_so
.PHONY: mac_dylib

android_so:
	cargo ndk --target aarch64-linux-android --platform 21 -- build --release
	cargo ndk --target armv7-linux-androideabi --platform 19 -- build --release
	cargo ndk --target i686-linux-android --platform 19 -- build --release
	cargo ndk --target x86_64-linux-android --platform 21 -- build --release
	mkdir -p ffi/android/lib/src/main/jniLibs/armeabi-v7a/
	cp target/armv7-linux-androideabi/release/libzkgroup.so \
		ffi/android/lib/src/main/jniLibs/armeabi-v7a/
	mkdir -p ffi/android/lib/src/main/jniLibs/arm64-v8a/
	cp target/aarch64-linux-android/release/libzkgroup.so \
		ffi/android/lib/src/main/jniLibs/arm64-v8a/
	mkdir -p ffi/android/lib/src/main/jniLibs/x86/
	cp target/i686-linux-android/release/libzkgroup.so \
		ffi/android/lib/src/main/jniLibs/x86/
	mkdir -p ffi/android/lib/src/main/jniLibs/x86_64/
	cp target/x86_64-linux-android/release/libzkgroup.so \
		ffi/android/lib/src/main/jniLibs/x86_64/

server_so:
	cargo build --target x86_64-unknown-linux-gnu --release
	mkdir -p ffi/java/src/main/resources/
	cp target/x86_64-unknown-linux-gnu/release/libzkgroup.so ffi/java/src/main/resources/

mac_dylib:
	cargo build --target x86_64-apple-darwin --release
	mkdir -p ffi/java/src/main/resources/
	cp target/x86_64-apple-darwin/release/libzkgroup.dylib ffi/java/src/main/resources/
