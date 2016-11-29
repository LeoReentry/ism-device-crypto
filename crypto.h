//
// Created by leo on 11/29/16.
//


#ifndef ENC_CRYPTO_H_H
#define ENC_CRYPTO_H_H

/// Encrypts data using AES-256 CBC. The key will be stored next
/// to the file and bound to the TPM. Every dataset that's encrypted
/// will be recognized via a name and every dataset will have its own
/// encryption key with the same name.
/// \param name Serves as "dictionary key". It's the name that will identify the dataset.
/// \param data Data to be encrypted.
void DeviceCrypto_Encrypt(char *name, unsigned char *data);
/// Decrypts data using AES-256 CBC. The function will look on the hard drive
/// if a dataset with the specified name has been encrypted. If so, the encryption
/// key assigned to that dataset will be unbound by the TPM and the data will be
/// decrypted.
/// \param name Serves as "dictionary key". Name of the dataset you want decrypted.
/// \param plaintext Will be allocated and filled with plaintext. It's the user's
/// obligation to remove the plaintext from memory and free the memory.
/// \param plaintext_length Length of the plaintext, will be set by function.
void DeviceCrypto_Decrypt(char *name, unsigned char** plaintext, int* plaintext_length);
/// The dataset with the given name will be decrypted and encrypted with a new AES key.
/// \param name Name of the dataset
void DeviceCrypto_RenewKey(char *name);
/// Creates a new AES encryption key, binds it to the TPM and stores it on the hard drive.
/// Can only be done if no dataset with that name already exists.
/// \param name Name of the dataset this encryption key will encrypt.
void DeviceCrypto_CreateKey(char *name);
#endif //ENC_CRYPTO_H_H
