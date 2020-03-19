CARGO ?= cargo
DOCKER ?= docker

.PHONY: default android_so server_so mac_dylib docker

default: docker

android_so:
	RUSTFLAGS='-C link-arg=-s' cargo ndk --target aarch64-linux-android --platform 21 -- build --release
	RUSTFLAGS='-C link-arg=-s' cargo ndk --target armv7-linux-androideabi --platform 19 -- build --release
	RUSTFLAGS='-C link-arg=-s' cargo ndk --target i686-linux-android --platform 19 -- build --release
	RUSTFLAGS='-C link-arg=-s' cargo ndk --target x86_64-linux-android --platform 21 -- build --release
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
	RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-unknown-linux-gnu --release
	mkdir -p ffi/java/src/main/resources/
	cp target/x86_64-unknown-linux-gnu/release/libzkgroup.so ffi/java/src/main/resources/

# @deprecated build
mac_dylib:
	RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-apple-darwin --release
	mkdir -p ffi/java/src/main/resources/
	cp target/x86_64-apple-darwin/release/libzkgroup.dylib ffi/java/src/main/resources/

libzkgroup:
	RUSTFLAGS='-C link-arg=-s' cargo build --release

docker: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
docker:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t zkgroup-builder .
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
	  --env "MAKEFLAGS=$(MAKEFLAGS)" \
	  -v `pwd`/:/home/zkgroup/src $(DOCKER_EXTRA) zkgroup-builder \
		sh -c "cd src; ./gradlew build"
