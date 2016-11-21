#include<stdio.h>
#include <openssl/rand.h>



int main(int argc, char **argv) {
    /* Key and IV */
    unsigned char key[32], iv[16];

    if (!RAND_bytes(key, sizeof key)) {
        /* OpenSSL reports a failure, act accordingly */
    }
    if (!RAND_bytes(iv, sizeof iv)) {
        /* OpenSSL reports a failure, act accordingly */
    }
    for(int i=0; i<sizeof key; i++) {
        printf("0x%2x ", key[i]);
    }
    printf("\n");
    for(int i=0; i<sizeof iv; i++) {
        printf("0x%2x ", iv[i]);
    }
    printf("\n");

    return 0;
}
