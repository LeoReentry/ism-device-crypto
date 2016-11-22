//
// Created by leo on 11/22/16.
//

#include "global.h"
#include <unistd.h>

int verbose = 0;
void print_info(char* str);
int UnbindAESKey(BYTE* key, int* length);


int main(int argc, char** argv) {
    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "v")) != -1)) {
        switch (opt) {
            // Switch -v for verbose
            case 'v': verbose = 1; break;
            default: break;
        }
    }
    // Initialize TPM context
    if (TPM_InitContext())
        ExitFailure();
    BYTE* key;
    int length;
    UnbindAESKey(key, &length);

    return 0;
}

void print_info(char* str) {
    if (verbose) {
        printf(str);
    }
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
//        closeTPM();
        printf("Error during data unbinding: Feed encrypted data into object. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
    }

    // Unbind data
    result = Tspi_Data_Unbind(hEncData, hBindKey, &keyLength, &key);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Unbind data. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    free(encKey);
    *length = keyLength;
    // Close handles
    Tspi_Key_UnloadKey(hBindKey);
    Tspi_Context_CloseObject(hContext, hBindKeyPolicy);
    Tspi_Context_CloseObject(hContext, hEncData);
    Tspi_Context_CloseObject(hContext, hBindKey);
    return 0;
}