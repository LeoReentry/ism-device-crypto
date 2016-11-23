//
// Created by leo on 11/23/16.
//

#include <memory.h>
#include <unistd.h>
#include <tss/tspi.h>
#include "tpm.h"
#include "global.h"
#include <stdio.h>
#include <trousers/trousers.h>

TSS_HKEY hSRK=0;
TSS_HPOLICY hSRKPolicy=0;
TSS_UUID SRK_UUID=TSS_UUID_SRK;

int TPM_InitContext(void) {
    // Set wks to the well known secret: 20 bytes of 0's
    memset(wks,0,20);

    // Pick the TPM you're talking to
    // In this case, it's the system TPM (indicated with NULL)

    result = Tspi_Context_Create( &hContext);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Context Create. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }

    result = Tspi_Context_Connect(hContext, NULL);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Context Connect. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }

    // Get the TPM handle
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Get TPM handle. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }

    // Get the SRK handle
    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Get SRK handle. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }

    // Get the SRK by policy
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Get SRK policy. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }

    // Then set the SRK policy to be the well known secret
    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_SHA1, 20, wks);
    // Note: TSS_SECRET_MODE_SHA1 says "Don't hash this"
    // Use 20 bytes as they are
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Set SRK secret. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }

    // Get the TPM by policy
    result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Get TPM policy. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }

    // Then set the TPM policy to be the well known secret
    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_SHA1, 20, wks);
    // Note: TSS_SECRET_MODE_SHA1 says "Don't hash this"
    // Use 20 bytes as they are
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Initialization: Set TPM secret. Error 0x%08x:%s\n", result, (char *)Trspi_Error_String(result));
        return 1;
    }
    return 0;
}

int TPM_CreateKey(void) {
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
    printf("Success.\n");

    // Register that key with UUID
    printf("Registering key blob for later retrieval... " );
    fflush(stdout);
    result = Tspi_Context_RegisterKey(hContext, hBindKey, TSS_PS_TYPE_SYSTEM, BindKey_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during Key creation: Register key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    printf("Success.\n");

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
int BindAESKey(BYTE* key, UINT32 key_size) {
    // TPM variables
    TSS_UUID BindKey_UUID = KEY_UUID;
    TSS_HKEY hBindKey;
    TSS_HOBJECT hEncData;
    // File handling
    FILE *f;
    UINT32 boundDataLength;
    BYTE *boundData;
    print_info("Bind AES key to TPM... ");
    fflush(stdout);
    // Get reference to key
    result = Tspi_Context_GetKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, BindKey_UUID, &hBindKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data binding: Get key by UUID. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Load the key with wrapping key
    result = Tspi_Key_LoadKey(hBindKey, hSRK);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data binding: Load key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Create a data object, fill it with clear text and then bind it
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data binding: Create data. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Bind data
    result = Tspi_Data_Bind(hEncData, hBindKey, key_size, key);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data binding: Bind data. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Get encrypted data out of data object
    result = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, &boundDataLength, &boundData);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data binding: Retrieve bound data. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Write encrypted data to file
    f = fopen(KEYPATH, "wb");
    write(fileno(f), boundData, boundDataLength);
    fclose(f);

    result = Tspi_Key_UnloadKey(hBindKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data binding: Unload key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    print_info("Success.\n");
    // If program was successful, clear AES key from memory. If it was unsuccessful, this isn't necessary, since the key will not be used
    memset(key, 0, key_size);
    Tspi_Context_CloseObject(hContext, hEncData);
    Tspi_Context_CloseObject(hContext, hBindKey);
    return 0;

}
int UnbindAESKey(BYTE** key, int* length) {
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
    result = Tspi_Data_Unbind(hEncData, hBindKey, &keyLength, key);
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
void TPM_CloseContext(void) {
    // Clean up
    Tspi_Context_CloseObject(hContext, hSRK);
    Tspi_Context_CloseObject(hContext, hSRKPolicy);
    Tspi_Context_CloseObject(hContext, hTPM);
    Tspi_Context_CloseObject(hContext, hTPMPolicy);
    // This automatically frees memory allocated
    Tspi_Context_FreeMemory(hContext, NULL);
    Tspi_Context_Close(hContext);
}