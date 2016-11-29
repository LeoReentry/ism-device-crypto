//
// Created by leo on 11/29/16.
//
#define _GNU_SOURCE
#include "global.h"
#include "tpm.h"
#include "aes.h"
#include "crypto.h"

void encrypt_data(char* filepath, char* keypath, unsigned char* data);
void decrypt_data(char *filepath, char *keypath, unsigned char** plaintext, int* plaintext_length);

void renew_key(char *name)
{
    // Get path variables
    char *keypath, *filepath;
    char *homepath = getenv("HOME");
    char *dirpath;
    asprintf(&dirpath, PATH, homepath);
    // Get path to key file and data file
    asprintf(&keypath, KEY_FILE, dirpath, name);
    asprintf(&filepath, DATA_FILE, dirpath, name);

    // Check that both key and file are present
    if (!fileExists(filepath) || !fileExists(keypath))
    {
        printf("No data or key file found. Can't renew key.\n");
        ExitFailure();
    }
    // If no TPM key exists, exit
    if(!UuidExists())
    {
        printf("No TPM key present to unbind encryption key. Can't renew.\n");
        ExitFailure();
    }

    // Decrypt data
    char* plaintext;
    int plaintext_length;
    print_info("Decrypting data.\n");
    decrypt_data(filepath, keypath, (unsigned char**)&plaintext, &plaintext_length);
    print_info("Data decrypted.\n");

    // Now backup old data in case something goes wrong
    int len = (strlen(filepath) + strlen(".tmp")) * sizeof(char);
    char* backupfile = malloc(len + 1);
    strncpy(backupfile, filepath, strlen(filepath));
    strncat(backupfile, ".tmp", 4);
    char* backupkey= malloc(len + 1);
    strncpy(backupkey, keypath, strlen(filepath));
    strncat(backupkey, ".tmp", 4);
    rename(filepath, backupfile);
    rename(keypath, backupkey);

    // Create new AES key
    unsigned char key[KEY_SIZE];
    if (AES_CreateKey(key))
        ExitFailure();
    print_info("Start data reencryption.\n");
    // Encrypt data and save to file
    if(AES_EncryptData((unsigned char*)plaintext, key, filepath)) {
        // Move backup files back
        rename(backupfile, filepath);
        rename(backupkey, keypath);
        free(backupfile);
        free(backupkey);
        // Overwrite key and plaintext with 0 in memory
        memset(key, 0, sizeof key);
        memset(plaintext, 0, strlen(plaintext));
        free(plaintext);
        // Close TPM Context and exit
        ExitFailure();
    }
    // Restart TPM context
    // This forces the TPM to reload the Storage Root Key in order to encrypt the AES key
    TPM_CloseContext();
    TPM_InitContext();
    // Bind this key to TPM
    // This will save the encrypted key to the hard drive
    if (TPM_BindAESKey((BYTE *) key, KEY_SIZE, keypath)) {
        // Move backup files back
        rename(backupfile, filepath);
        rename(backupkey, keypath);
        free(backupfile);
        free(backupkey);
        // Overwrite key and plaintext with 0 in memory
        memset(key, 0, sizeof key);
        memset(plaintext, 0, strlen(plaintext));
        free(plaintext);
        ExitFailure();
    }
    // Delete backup files
    remove(backupfile);
    remove(backupkey);
    free(backupfile);
    free(backupkey);
    // Overwrite key and plaintext with 0 in memory
    memset(key, 0, sizeof key);
    memset(plaintext, 0, strlen(plaintext));
    free(plaintext);

}
void create_key(char *name)
{
    // Get path variables
    char *keypath, *filepath;
    char *homepath = getenv("HOME");
    char *dirpath;
    asprintf(&dirpath, PATH, homepath);
    // Get path to key file and data file
    asprintf(&keypath, KEY_FILE, dirpath, name);
    asprintf(&filepath, DATA_FILE, dirpath, name);

    // Check that both key and file are present
    if (fileExists(keypath))
    {
        printf("A key with that name already exists. If you want to create a new key with the same name, please use "
                       "the switch -r. This will renew the key and reencrypt the associated data if necessary.\n");
        ExitFailure();
    }
    // If no TPM key exists, create a new one
    if(!UuidExists()) {
        print_info("No TPM key present.\nCreating new TPM key.\n");
        if (TPM_CreateKey())
            ExitFailure();
    }
    // Key
    unsigned char key[KEY_SIZE];
    // Create new AES key
    if (AES_CreateKey(key))
        ExitFailure();
    // Bind this key to TPM
    // This will save the encrypted key to the hard drive
    if (TPM_BindAESKey((BYTE *) key, KEY_SIZE, keypath))
        ExitFailure();
    // Remove key from memory
    memset(key, 0, KEY_SIZE);
}
void encrypt_dat(char *name, unsigned char *data)
{
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
void decrypt_dat(char *name, unsigned char** plaintext, int* plaintext_length)
{
    // Get path variables
    char *keypath=NULL, *filepath=NULL;
    char *homepath = getenv("HOME");
    char *dirpath=NULL;
    asprintf(&dirpath, PATH, homepath);
    // Get path to key file and data file
    asprintf(&keypath, KEY_FILE, dirpath, name);
    asprintf(&filepath, DATA_FILE, dirpath, name);
    decrypt_data(filepath, keypath, plaintext, plaintext_length);
    // Free all other stuff
    free(keypath);
    free(filepath);
    free(dirpath);
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

