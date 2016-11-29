#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include "global.h"
#include "tpm.h"
#include "crypto.h"

/// Checks if exclusive switches have been set correctly
void check_switches(int es);

int main(int argc, char** argv) {
    // Variable to check exclusive switches and one to check whether user has set a name for the key
    int exclusive_switch = 0, name = 0;
    // Path to keyfile and datafile and name
    char *keyname = NULL;
    // Program behaviour
    int encryption = 0, decryption = 0, key_creation = 0, key_renewal = 0;
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
                key_creation = 1;
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
                printf("%s", HELP_STRING);
                exit(EXIT_SUCCESS);
            // Switch -k for help
            case 'n':
                print_info("Using name ");
                print_info(optarg);
                print_info(".\n");
                // Define that name is set by user
                name = 1;
                // Save name for later use
                keyname = optarg;
                break;
            // Switch -r for renewing a key
            case 'r':
                check_switches(exclusive_switch);
                exclusive_switch = 1;
                key_renewal = 1;
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
    // If name was not defined, use default name
    if (!name) {
        keyname = malloc(8*sizeof(char));
        strcpy(keyname, DEFAULT_NAME);
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
            printf("%s", HELP_STRING);
            exit(EXIT_FAILURE);
        }
        // Encrypt data and store it to file
        encrypt_dat(keyname, (unsigned char*) argv[optind]);
    }
    else if (decryption) {
        char* plaintext;
        int plaintext_length;
        decrypt_dat(keyname, (unsigned char**)&plaintext, &plaintext_length);
        printf("%s\n", plaintext);
        // Overwrite key and plaintext with 0 in memory
        memset(plaintext, 0, (size_t)plaintext_length);
        // Free plaintext
        free(plaintext);

    }
    else if (key_renewal) {
        renew_key(keyname);
    }
    else if (key_creation) {
        create_key(keyname);
    }

    TPM_CloseContext();
    if(!name)
        free(keyname);
    exit(EXIT_SUCCESS);
}

void check_switches(int es) {
    if (es) {
        printf("Error. Please use only one of -c -d -e -r.\n");
        exit(EXIT_FAILURE);
    }
}
