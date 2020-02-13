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
	python ./codegen.py

install:
	cp ffiapijava/ffiapijava.rs ../src/ffi/
	cp ffiapi/ffiapi.rs ../src/ffi/
	cp simpleapi/simpleapi.rs ../src/ffi/
	cp -r java/* ../java/src/main/java/org/signal/zkgroup

clean:
	rm -rf ffiapijava
	rm -rf ffiapi
	rm -rf java
	rm -rf simpleapi
	rm -rf swift
