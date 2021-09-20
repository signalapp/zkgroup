.PHONY: all
all:
	$(MAKE) output
	$(MAKE) install
	$(MAKE) clean

.PHONY: output
output:
	mkdir -p ffiapijava
	mkdir -p ffiapi
	mkdir -p java
	mkdir -p java/auth
	mkdir -p java/profiles
	mkdir -p java/groups
	mkdir -p java/internal
	mkdir -p simpleapi
	mkdir -p swift
	python3 ./codegen.py
	rustfmt ffiapijava/ffiapijava.rs
	rustfmt ffiapi/ffiapi.rs
	rustfmt simpleapi/simpleapi.rs

.PHONY: install
install:
	cp ffiapijava/ffiapijava.rs ../rust/src/ffi/
	cp ffiapi/ffiapi.rs ../rust/src/ffi/
	cp simpleapi/simpleapi.rs ../rust/src/ffi/
	cp -r java/* ../ffi/java/src/main/java/org/signal/zkgroup
	cp -r swift/* ../ffi/swift/Sources/ZKGroup
	patch -d .. -p1 < codegen_hack.patch

.PHONY: clean
clean:
	rm -rf ffiapijava
	rm -rf ffiapi
	rm -rf java
	rm -rf simpleapi
	rm -rf swift
