/*
 * This program will create a TPM key. Then it will create an AES-256 key and bind it with the TPM.
 */
#include "global.h"
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/err.h>


/// \brief Checks if a key exists.
///
/// Checks if both the TPM and the AES key exist. If one of them exists, it will prompt the user to
/// run the program with the switch -f to force key creation and return 1. If the switch -f is present,
/// it will ignore whether the key exists or not.
/// \return integer
int CheckKey(void);
/// Creates an AES key using the openSSL provided random function. It feeds off of /dev/urandom, so make sure enough
/// entropy is available. Otherwise it fail if it can't generate more itself
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int CreateAESKey(void);

int override = 0; ///< Tells whether to override existing key or not.
unsigned char key[KEY_SIZE]; ///< Contains the AES encryption key. 256 bit / 8 = 32B

int main(int argc, char **argv) {
    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "f")) != -1)) {
        switch (opt) {
            // Switch -f will force program to override old keys
            case 'f': override = 1; break;
            default: break;
        }
    }
    // Initialize TPM context
    if (TPM_InitContext())
        ExitFailure();
    // Check if keys already exist and only continue if switch -f is present
    if (CheckKey())
        ExitFailure();
    // Create TPM key
    if (TPM_CreateKey())
        ExitFailure();
    // Create AES key
    if (CreateAESKey())
        ExitFailure();
    // Bind AES key
    if (BindAESKey())
        ExitFailure();
    // Close all open TPM handles
    TPM_CloseContext();
    return EXIT_SUCCESS;
}


int CheckKey(void) {
    // Check if key exists by loading it from UUID and checking if the keyfile is present.
    TSS_HKEY hKey;
    TSS_RESULT result;
    TSS_UUID uuid = KEY_UUID;
    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, uuid, &hKey);
    Tspi_Context_CloseObject(hContext, hKey);

    // If key exists
    int exists = fileExists(KEYPATH) | (result == TSS_SUCCESS);

    if (exists && !override) {
        printf("Key already exists. If you wish to override the existing key, please run this program with switch -f. This will create a new AES-256 key and a new TPM key.\n");
        return 1;
    } else if (exists) {
        int c;
        printf("Overriding old key. All data encrypted with it will be lost. Proceed? (y/n) ");
        c = getchar();
        if (c != 'y' && c != 'Y')
            return 1;
    }
    return 0;
}
int CreateAESKey(void) {
    printf("Creating AES key... ");
    fflush(stdout);
    if (!RAND_bytes(key, sizeof key)) {
        // Minimum of 120 byte when using error string
        char *err = malloc(120*sizeof(char));
        ERR_error_string(ERR_get_error(), err);
        printf("Error during AES key creation: %s\n", err);
        free(err);
        return 1;
    }
    printf("Success.\n");
    return 0;
}
