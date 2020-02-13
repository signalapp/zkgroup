
.PHONY: so
.PHONY: org_signal_zkgroup_ZKGroup.h

so:
	cargo build --target aarch64-linux-android --release
	cargo build --target armv7-linux-androideabi --release
	cargo build --target i686-linux-android --release
	cargo build --target x86_64-linux-android --release
	cp ../../target/armv7-linux-androideabi/release/libzkgroup.so \
		zkgroup/src/main/jniLibs/armeabi-v7a/
	cp ../../target/aarch64-linux-android/release/libzkgroup.so \
		zkgroup/src/main/jniLibs/arm64-v8a/
	cp ../../target/i686-linux-android/release/libzkgroup.so \
		zkgroup/src/main/jniLibs/x86/
	cp ../../target/x86_64-linux-android/release/libzkgroup.so \
		zkgroup/src/main/jniLibs/x86_64/

org_signal_zkgroup_ZKGroup.h:
	javac -h . zkgroup/src/main/java/org/signal/zkgroup/ZKGroup.java

