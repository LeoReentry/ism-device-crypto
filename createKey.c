/*
 * This program will create a TPM key. Then it will create an AES-256 key and bind it with the TPM.
 *
 */
#include "global.h"

int main(int argc, char **argv) {
    TPM_InitContext();
    TPM_CloseContext();
    return 0;
}

