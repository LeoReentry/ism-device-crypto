//
// Created by leo on 11/29/16.
//
#define _GNU_SOURCE
#include "global.h"
#include "tpm.h"
#include "aes.h"
#include "crypto.h"
void encrypt_dat(char *name, unsigned char *data) {
    // Get path variables
    char *keypath, *filepath;
    char *homepath = getenv("HOME");
    char *dirpath;
    asprintf(&dirpath, PATH, homepath);
    // Get path to key file and data file
    asprintf(&keypath, KEY_FILE, dirpath, name);
    asprintf(&filepath, DATA_FILE, dirpath, name);
    encrypt_data(filepath, keypath, data);

}
void decrypt_dat(char *name, unsigned char** plaintext, int* plaintext_length) {
    // Get path variables
    char *keypath, *filepath;
    char *homepath = getenv("HOME");
    char *dirpath;
    asprintf(&dirpath, PATH, homepath);
    // Get path to key file and data file
    asprintf(&keypath, KEY_FILE, dirpath, name);
    asprintf(&filepath, DATA_FILE, dirpath, name);
    decrypt_data(filepath, keypath, plaintext, plaintext_length);
}
void encrypt_data(char *filepath, char *keypath, unsigned char *data)
{
    // If no TPM key exists, create a new one
    if(!UuidExists()) {
        print_info("No TPM key present.\nCreating new TPM key.\n");
        if (TPM_CreateKey())
            ExitFailure();
    }
    // Key
    unsigned char key[KEY_SIZE];
    // If no key file exists, create a new one
    if (!fileExists(keypath)) {
        // Create new AES key
        if (AES_CreateKey(key))
            ExitFailure();
        // Bind this key to TPM
        // This will save the encrypted key to the hard drive
        if (TPM_BindAESKey((BYTE *) key, KEY_SIZE, keypath))
            ExitFailure();
    }
        // If the file already exists, just unbind the key and we can use it
    else {
        print_info("Using existent AES key.\n");
        int key_length;
        if(TPM_UnbindAESKey((BYTE**)&key, &key_length, keypath)) {
            // Overwrite key and plaintext with 0 in memory
            memset(key, 0, sizeof key);
            memset(data, 0, strlen((char*)data));
            ExitFailure();
        }
        if (key_length != KEY_SIZE) {
            printf("Error. The encryption key on the hard drive has the wrong size.\n");
            // Overwrite key and plaintext with 0 in memory
            memset(key, 0, sizeof key);
            memset(data, 0, strlen((char*)data));
            ExitFailure();
        }
    }
    // Encrypt data and save to file
    AES_EncryptData(data, key, filepath);
    // Overwrite key and plaintext with 0 in memory
    memset(key, 0, sizeof key);
    memset(data, 0, strlen((char*)data));
}

void decrypt_data(char *filepath, char *keypath, unsigned char** plaintext, int* plaintext_length)
{
    // First, check that both key and data are present
    if (!fileExists(filepath) || !fileExists(keypath)) {
        printf("Either the key or the encrypted file is missing. Aborting...\n");
        ExitFailure();
    }
    // If no TPM key exists, create a new one
    if(!UuidExists()) {
        print_info("No TPM key present.\nCreating new TPM key.\n");
        fflush(stdout);
        if (TPM_CreateKey())
            ExitFailure();
    }
    // Ok, everything is good. Now, load the key
    BYTE* key;
    int key_length;
    if(TPM_UnbindAESKey(&key, &key_length, keypath))
        ExitFailure();
    // We've got the key, let's decrypt our data
    if (AES_DecryptData(plaintext, key, filepath, plaintext_length)) {
        memset(key, 0, KEY_SIZE);
        free(*plaintext);
        ExitFailure();
    }
    // Overwrite key with 0, but don't call free()
    // Memory will be released upon calling TPM_CloseContext()
    memset(key, 0, KEY_SIZE);
}

