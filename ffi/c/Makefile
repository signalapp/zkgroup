
.PHONY: ctest
.PHONY: zkgroup.h 

ctest:
	gcc main.c ../../target/release/libzkgroup.a -o ctest -ldl -lpthread -lm

zkgroup.h:
	cbindgen --lang c ../.. -o zkgroup.h
