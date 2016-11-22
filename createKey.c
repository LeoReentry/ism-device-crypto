/*
 * This program will create a TPM key. Then it will create an AES-256 key and bind it with the TPM.
 */
#include "global.h"
#include <unistd.h>

/// Creates a new TPM key.
/// \return integer
int TPM_CreateKey(void);
/// \brief Checks if a key exists.
///
/// Checks if both the TPM and the AES key exist. If one of them exists, it will prompt the user to
/// run the program with the switch -f to force key creation and return 1. If the switch -f is present,
/// it will ignore whether the key exists or not.
/// \return integer
int CheckKey(void);
/// Closes open handles and exits with failure code.
void ExitFailure(void);

int override = 0; ///< Tells whether to override existing key or not.

int main(int argc, char **argv) {
    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "f")) != -1)) {
        switch (opt) {
            // Switch -f will force program to override old key
            case 'f': override = 1; break;
            default: break;
        }
    }
    // Initialize TPM context
    if(TPM_InitContext())
        ExitFailure();
    // Check if key exists
    if (CheckKey())
        ExitFailure();
    // Create TPM key
    if(TPM_CreateKey())
        ExitFailure();
    
    // Close all open TPM handles
    TPM_CloseContext();
    return 0;
}

void ExitFailure(void) {
    TPM_CloseContext();
    exit(EXIT_FAILURE);
}
int CheckKey(void) {
    // Check if key exists by loading it from UUID and checking if the keyfile is present.
    TSS_HKEY hKey;
    TSS_RESULT result;
    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, KEY_UUID, &hKey);
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
int TPM_CreateKey(){
    // TPM variables
    TSS_HKEY hBindKey;
    TSS_HPOLICY hKeyPolicy;
    TSS_UUID BindKey_UUID = KEY_UUID;
    TSS_FLAG initFlags = TSS_KEY_TYPE_BIND |
                         TSS_KEY_SIZE_2048 |
                         TSS_KEY_AUTHORIZATION |
                         TSS_KEY_NOT_MIGRATABLE |
                         TSS_KEY_STRUCT_KEY12;

    // Unregister old bind key if it exists
    Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_SYSTEM, BindKey_UUID, &hBindKey);

    // Create key policy object
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hKeyPolicy);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Create key policy object. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Create key object
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hBindKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Create key object. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Set key scheme
    result = Tspi_SetAttribUint32(hBindKey, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_ENCSCHEME, TSS_ES_RSAESOAEP_SHA1_MGF1);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Set key padding type. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Assign policy to key
    result = Tspi_Policy_AssignToObject(hKeyPolicy, hBindKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Assign policy to key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Set secret for key
    result = Tspi_Policy_SetSecret(hKeyPolicy, TSS_SECRET_MODE_PLAIN, 20, wks);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Set key secret. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    printf("Creating new key. This could take a while... ");
    fflush(stdout);
    // Create new key in TPM
    result = Tspi_Key_CreateKey(hBindKey, hSRK, 0);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Create key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    printf("Done.\n");

    // Register that key with UUID
    printf("Registering key blob for later retrieval... " );
    fflush(stdout);
    result = Tspi_Context_RegisterKey(hContext, hBindKey, TSS_PS_TYPE_SYSTEM, BindKey_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Register key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    printf("Done.\n");

    // Flush the secret
    result = Tspi_Policy_FlushSecret(hKeyPolicy);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Flush Secret. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Close handles
    Tspi_Context_CloseObject(hContext, hKeyPolicy);
    Tspi_Context_CloseObject(hContext, hBindKey);
    return 0;
}
