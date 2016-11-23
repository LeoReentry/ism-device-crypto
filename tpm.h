//
// Created by leo on 11/23/16.
//

#ifndef ENC_TPM_H
#define ENC_TPM_H

#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>

/// Checks if a key with the UUID already exists in the TPM
/// \return integer, 1 for true, 0 for false
int UuidExists(void);
/// \brief Initializes handles that are necessary for all TPM operations.
///
/// Initializes handles for Context and SRK, gets their policies and sets their policy secrets to the well-known secrets.
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int TPM_InitContext(void);
/// Creates a new TPM key.
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int TPM_CreateKey(void);
/// Binds the AES key to the TPM.
/// \param key Pointer to the key to bind.
/// \param key_size Size of key in bytes.
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int BindAESKey(BYTE* key, UINT32 key_size);
/// Decrypts AES key from file to memory.
/// \param key Buffer in which key is written. Memory allocated by function.
/// \param length Length of key. Is set by function.
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int UnbindAESKey(BYTE** key, int* length);
/// \brief Closes the handles opened before.
/// \return void
void TPM_CloseContext(void);
/// \brief Checks if a file exists
/// @param filename String with the complete path to the file
/// \returns integer
/// \retval 1 for true
/// \retval 0 for false

TSS_HCONTEXT hContext;
TSS_HTPM hTPM;
TSS_HPOLICY hTPMPolicy;
TSS_RESULT result;
TSS_HKEY hSRK;
TSS_HPOLICY hSRKPolicy;
TSS_UUID SRK_UUID;
BYTE wks[20]; //For the well known secret

#endif //ENC_TPM_H
