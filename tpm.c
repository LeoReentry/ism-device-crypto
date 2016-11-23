//
// Created by leo on 11/23/16.
//

#include <memory.h>
#include <tss/tspi.h>
#include "tpm.h"
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