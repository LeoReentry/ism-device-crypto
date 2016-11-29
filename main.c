#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include "global.h"
#include "crypto.h"

/// Checks if exclusive switches have been set correctly
void check_switches(int es);

int main(int argc, char** argv) {
    // Variable to check exclusive switches and one to check whether user has set a name for the key
    int exclusive_switch = 0, name_defined = 0;
    // Path to keyfile and datafile and name
    char *name = NULL;
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
                name_defined = 1;
                // Save name for later use
                name = optarg;
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
    if (!name_defined) {
        name = malloc(8*sizeof(char));
        strcpy(name, DEFAULT_NAME);
    }

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
        DeviceCrypto_Encrypt(name, (unsigned char*) argv[optind]);
    }
    else if (decryption) {
        char* plaintext;
        int plaintext_length;
        DeviceCrypto_Decrypt(name, (unsigned char**)&plaintext, &plaintext_length);
        printf("%s\n", plaintext);
        // Overwrite key and plaintext with 0 in memory
        memset(plaintext, 0, (size_t)plaintext_length);
        // Free plaintext
        free(plaintext);
    }
    else if (key_renewal) {
        DeviceCrypto_RenewKey(name);
    }
    else if (key_creation) {
        DeviceCrypto_CreateKey(name);
    }

    // If name was not defined, it was allocated manually
    if(!name_defined)
        free(name);
    exit(EXIT_SUCCESS);
}

void check_switches(int es) {
    if (es) {
        printf("Error. Please use only one of -c -d -e -r.\n");
        exit(EXIT_FAILURE);
    }
}
