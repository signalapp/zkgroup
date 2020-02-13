#include "zkgroup.h"
#include <stdio.h>


int main() {

    unsigned char testbufi[] = {0,1,2};
    unsigned char testbufo[] = {0,0,0};
    zktestfunc(testbufi, 3, testbufo, 3);
    printf("Result (should be 1 2 3) = %d %d %d\n", testbufo[0], testbufo[1], testbufo[2]);

    unsigned char clientkeypair[CLIENT_KEY_PAIR_LEN];
    unsigned char serverkeypair[SERVER_KEY_PAIR_LEN];
    unsigned char randomness[RANDOMNESS_LEN];
    ClientKeyPair_derive(randomness, 32, clientkeypair, CLIENT_KEY_PAIR_LEN);
    ServerKeyPair_generate(randomness, 32, serverkeypair, SERVER_KEY_PAIR_LEN);

    unsigned char clientpublickey[CLIENT_PUBLIC_KEY_LEN];
    unsigned char serverpublickey[SERVER_PUBLIC_KEY_LEN];
    ClientKeyPair_getPublicKey(clientkeypair, CLIENT_KEY_PAIR_LEN, clientpublickey, CLIENT_PUBLIC_KEY_LEN);
    ServerKeyPair_getPublicKey(serverkeypair, SERVER_KEY_PAIR_LEN, serverpublickey, SERVER_PUBLIC_KEY_LEN);
}
