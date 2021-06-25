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

server_so_simd:
	cd rust && RUSTFLAGS='-C link-arg=-s -C target_feature=+avx512ifma' cargo +nightly build --target x86_64-unknown-linux-gnu --release --no-default-features --features "simd_backend"

# @deprecated build
mac_dylib:
	RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-apple-darwin --release
	mkdir -p ffi/java/src/main/resources/
	cp target/x86_64-apple-darwin/release/libzkgroup.dylib ffi/java/src/main/resources/

libzkgroup:
	RUSTFLAGS='-C link-arg=-s' cargo build --release

DOCKER_IMAGE := zkgroup-builder

docker_build:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t $(DOCKER_IMAGE) .

docker: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
docker: docker_build
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
	  --env "MAKEFLAGS=$(MAKEFLAGS)" \
	  -v `pwd`/:/home/zkgroup/src $(DOCKER_EXTRA) $(DOCKER_IMAGE) \
		sh -c "cd src; ./gradlew build"

docker_test: docker_build
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
	  --env "MAKEFLAGS=$(MAKEFLAGS)" \
	  -v `pwd`/:/home/zkgroup/src $(DOCKER_EXTRA) $(DOCKER_IMAGE) \
		sh -c "cd src; ./gradlew test"


SONATYPE_USERNAME    ?=
SONATYPE_PASSWORD    ?=
KEYRING_FILE         ?=
SIGNING_KEY          ?=
SIGNING_KEY_PASSWORD ?=

publish: DOCKER_EXTRA = $(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
publish: KEYRING_VOLUME := $(dir $(KEYRING_FILE))
publish: KEYRING_FILE_ROOT := $(notdir $(KEYRING_FILE))
publish:
	@[ -n "$(SONATYPE_USERNAME)" ]    || ( echo "SONATYPE_USERNAME is not set" && false )
	@[ -n "$(SONATYPE_PASSWORD)" ]    || ( echo "SONATYPE_PASSWORD is not set" && false )
	@[ -n "$(KEYRING_FILE)" ]         || ( echo "KEYRING_FILE is not set" && false )
	@[ -n "$(SIGNING_KEY)" ]          || ( echo "SIGNING_KEY is not set" && false )
	@[ -n "$(SIGNING_KEY_PASSWORD)" ] || ( echo "SIGNING_KEY_PASSWORD is not set" && false )
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
		--env "MAKEFLAGS=$(MAKEFLAGS)" \
		-v `pwd`/:/home/zkgroup/src $(DOCKER_EXTRA) \
		-v $(KEYRING_VOLUME):/home/zkgroup/keyring \
		$(DOCKER_IMAGE) \
		sh -c "cd src; ./gradlew uploadArchives \
			-PwhisperSonatypeUsername='$(SONATYPE_USERNAME)' \
			-PwhisperSonatypePassword='$(SONATYPE_PASSWORD)' \
			-Psigning.secretKeyRingFile='/home/zkgroup/keyring/$(KEYRING_FILE_ROOT)' \
			-Psigning.keyId='$(SIGNING_KEY)' \
			-Psigning.password='$(SIGNING_KEY_PASSWORD)'"
