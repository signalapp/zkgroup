
.PHONY: so
.PHONY: jar
.PHONY: test

so:
	cargo build --release
	cp ../../target/release/libzkgroup.so \
		src/main/resources/ 

jar:
	mvn package

test:
	mvn test

