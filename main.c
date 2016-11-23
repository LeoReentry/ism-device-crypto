#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include "global.h"
#include "tpm.h"

/// Checks if exclusive switches have been set correctly
void check_switches(int es);

int main(int argc, char** argv) {
    // Variable to check exclusive switches and one to check whether user has set a name for the key
    int exclusive_switch = 0, name = 0;
    // Path to keyfile and datafile
    char *keypath, *filepath;
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
                asprintf(&keypath, KEY_FILE, dir_path, DEFAULT_NAME);
                asprintf(&filepath, DATA_FILE, dir_path, DEFAULT_NAME);
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
        asprintf(&keypath, KEY_FILE, dir_path, optarg);
        asprintf(&filepath, DATA_FILE, dir_path, optarg);
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
    // If no TPM key exists, create a new one
    if(!UuidExists()) {
        print_info("No TPM key present. Creating new one... ");
        fflush(stdout);
        if (TPM_CreateKey())
            ExitFailure();
        print_info("Success\n");
    }


    // Ok, we're done, now we can finally do stuff
    // Check the type of operation we'll have to do (only one is possible)
    // AKA this is how a shitty state machine looks like
    if (encryption) {

    }
    else if (decryption) {

    }
    else if (renew_key) {

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