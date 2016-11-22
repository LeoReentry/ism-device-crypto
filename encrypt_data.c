//
// Created by leo on 11/22/16.
//

#include "global.h"
#include <unistd.h>

/// Decrypts AES key from file to memory.
/// \param key Buffer in which key is written. Memory allocated by function.
/// \param length Length of key. Is set by function.
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int UnbindAESKey(BYTE* key, int* length);


int main(int argc, char** argv) {
    if (!fileExists(KEYPATH)) {
        printf("Error. Couldn't find key file. Please make sure your encryption key is present.\n");
        exit(EXIT_FAILURE);
    }
    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "asdfhv")) != -1)) {
        switch (opt) {
            // Switch -h for help
            case 'h':
                printf("\n\nThis program encrypts data using AES-256 in CBC mode. The encryption key is the key created using create_key. "\
                       "It will be unbound by the TPM for the time of the encryption and then be bound again.\n\n" \
                       "Usage:\n\tencrypt_data -v data\n" \
                       "\t\t-h\tHelp. Displays this help.\n" \
                       "\t\t-v\tVerbose. Displays information during the process.\n" \
                       "\tThe data must be passed as last command line argument.\n");
                exit(EXIT_SUCCESS);
            // Switch -v for verbose
            case 'v':
                verbose = 1;
                break;
            default: break;
        }
    }
    // Check that we have an additional argument
    if (!(argc-optind)){
        printf("Please pass the data to be encrypted as a string.");
        exit(EXIT_FAILURE);
    }

    // Initialize TPM context
    if (TPM_InitContext())
        ExitFailure();

    // GET AES key
    BYTE* key;
    int length;
    if(UnbindAESKey(key, &length))
        ExitFailure();

    

    return 0;
}


int UnbindAESKey(BYTE* key, int* length) {
    // TPM variables
    TSS_HKEY hBindKey = 0;
    TSS_UUID BindKey_UUID = KEY_UUID;
    TSS_HOBJECT hEncData = 0;
    TSS_HPOLICY hBindKeyPolicy = 0;
    // Encrypted data
    FILE *fin;
    UINT32 encKeyLength;
    BYTE *encKey;
    // Unencrypted key
    UINT32 keyLength;

    print_info("Reading AES key from file... ");
    fflush(stdout);
    // Read encrypted data from file
    fin = fopen(KEYPATH, "r");
    fseek(fin, 0, SEEK_END);
    encKeyLength = (uint32_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);
    encKey = (BYTE*)malloc(encKeyLength*sizeof(BYTE));
    if (encKey) {
        fread (encKey, 1, encKeyLength, fin);
    }
    fclose(fin);
    print_info("Success.\nUnbinding AES key... ");
    fflush(stdout);

    // Get key
    result = Tspi_Context_GetKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, BindKey_UUID, &hBindKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Get key by UUID. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Load the key with wrapping key
    result = Tspi_Key_LoadKey(hBindKey, hSRK);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Load key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Get policy
    result = Tspi_GetPolicyObject(hBindKey, TSS_POLICY_USAGE, &hBindKeyPolicy);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Get key policy. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Set policy secret
    Tspi_Policy_SetSecret( hBindKeyPolicy, TSS_SECRET_MODE_PLAIN, 20, wks  );
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Set key secret. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Create data object.
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Create data object. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Feed encrypted data into data object.
    result = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, encKeyLength, encKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Feed encrypted data into object. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Unbind data
    result = Tspi_Data_Unbind(hEncData, hBindKey, &keyLength, &key);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Unbind data. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    print_info("Success.\n");
    free(encKey);
    *length = keyLength;
    // Close handles
    Tspi_Key_UnloadKey(hBindKey);
    Tspi_Context_CloseObject(hContext, hBindKeyPolicy);
    Tspi_Context_CloseObject(hContext, hEncData);
    Tspi_Context_CloseObject(hContext, hBindKey);
    return 0;
}