#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include "global.h"
#include "tpm.h"
#include "aes.h"

/// Checks if exclusive switches have been set correctly
void check_switches(int es);
void encrypt_data(char* filepath, char* keypath, unsigned char* data);
void decrypt_data(char *filepath, char *keypath, unsigned char** plaintext, int* plaintext_length);

int main(int argc, char** argv) {
    // Variable to check exclusive switches and one to check whether user has set a name for the key
    int exclusive_switch = 0, name = 0;
    // Path to keyfile and datafile
    char *keypath = NULL, *filepath = NULL;
    // Program behaviour
    int encryption = 0, decryption = 0, create_key = 0, renew_key = 0;
    // Directories
    // Path to home directory
    char *home_path = getenv ("HOME");
    // Path to directory for settings of this program
    // Asprintf allocates memory by itself
    char *dir_path;
    asprintf(&dir_path, PATH, home_path);

    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "cdehn:rv")) != -1)) {
        switch (opt) {
            // Switch -c for creating new key
            case 'c':
                check_switches(exclusive_switch);
                exclusive_switch = 1;
                create_key = 1;
                break;
            // Switch -d for decryption
            case 'd':
                check_switches(exclusive_switch);
                exclusive_switch = 1;
                decryption = 1;
                break;
            // Switch -e for encryption
            case 'e':
                check_switches(exclusive_switch);
                exclusive_switch = 1;
                encryption = 1;
                break;
            // Switch -h for help
            case 'h':
                printf(HELP_STRING);
                exit(EXIT_SUCCESS);
            // Switch -k for help
            case 'n':
                print_info("Using name ");
                print_info(optarg);
                print_info(".\n");
                // Get path to key file and data file
                asprintf(&keypath, KEY_FILE, dir_path, optarg);
                asprintf(&filepath, DATA_FILE, dir_path, optarg);
                // Define that name is set by user
                name = 1;
                break;
            // Switch -r for renewing a key
            case 'r':
                check_switches(exclusive_switch);
                exclusive_switch = 1;
                renew_key = 1;
                break;
            // Switch -v for verbose
            case 'v':
                verbose = 1;
                break;
            default:
                break;
        }
    }
    // Program defaults to encryption mode
    if (!exclusive_switch)
        encryption = 1;
    if (!name) {
        asprintf(&keypath, KEY_FILE, dir_path, DEFAULT_NAME);
        asprintf(&filepath, DATA_FILE, dir_path, DEFAULT_NAME);
    }

    // Create data directory if not existent
    DIR* dir = opendir(dir_path);
    if (dir) // Directory exists, just close it again
        closedir(dir);
    else if(ENOENT == errno) {
        int stat = mkdir(dir_path, 0777);
        if ( !stat ); // Everything ok.
        else { // Can't create directory
            printf("Error. Can't create settings directory in path:\n%s\nPlease fix before running this program again.\n", dir_path);
            exit(EXIT_FAILURE);
        }
    }

    // Initialize TPM
    if(TPM_InitContext())
        ExitFailure();


    // Ok, we're done, now we can finally do stuff
    // Check the type of operation we'll have to do (only one is possible)
    // AKA this is how a shitty state machine looks like
    if (encryption) {
        // Check that we have an additional argument
        if (!(argc-optind)){
            printf(HELP_STRING);
            exit(EXIT_FAILURE);
        }
        char* data = argv[optind];
        // Encrypt data and store it to file
        encrypt_data(filepath, keypath, (unsigned char*)data);
    }
    else if (decryption) {
        char* plaintext;
        int plaintext_length;
        decrypt_data(filepath, keypath, (unsigned char**)&plaintext, &plaintext_length);
        printf("%s\n", plaintext);
        // Overwrite key and plaintext with 0 in memory
        memset(plaintext, 0, (size_t)plaintext_length);
        // Free plaintext
        free(plaintext);

    }
    else if (renew_key) {
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

    }
    else if (create_key) {

    }

    TPM_CloseContext();
    free(dir_path);
    free(keypath);
    free(filepath);
    exit(EXIT_SUCCESS);
}

void check_switches(int es) {
    if (es) {
        printf("Error. Please use only one of -c -d -e -r.\n");
        exit(EXIT_FAILURE);
    }
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
        if(TPM_UnbindAESKey((BYTE**)&key, &key_length, keypath))
            ExitFailure();
        if (key_length != KEY_SIZE) {
            printf("Error. The encryption key on the hard drive has the wrong size.\n");
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