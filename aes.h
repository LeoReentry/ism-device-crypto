//
// Created by leo on 11/23/16.
//

#ifndef ENC_AES_H
#define ENC_AES_H

/// Creates a new 256 bit AES key. WARNING! Somethin will seriously go wrong if you don't have memory allocated for the key.
/// \param key Pointer to key
/// \return integer, 0 for success, 1 for failure
int AES_CreateKey(unsigned char *key);
/// Encrypts data using the openSSL library and AES-256 in CBC mode. Will save the data to file inlcuding IV.
/// \param plaintext Plaintext to be encrypted.
/// \param key Encryption key.
/// \param filepath Path in which encrypted file will be saved.
/// \return integer, 0 for success, 1 for failure
int AES_EncryptData(unsigned char* plaintext, unsigned char* key, char* filepath);
/// Decryptes data using the openSSL library and AES-256 in CBC mode. Will get the data from file.
/// \param plaintext Resulting plaintext. Pointer will be assigned and allocated by funtion.
/// \param key Key used for decryption
/// \param filepath Path to file in which the encrypted data is stored
/// \param length Length of resulting plaintext
/// \return integer, 0 for success, 1 for failure
int AES_DecryptData(unsigned char** plaintext, unsigned char* key, char* filepath, int* length);
#endif //ENC_AES_H
