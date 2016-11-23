//
// Created by leo on 11/23/16.
//

#include "global.h"
#include <unistd.h>

// variables for switches to make sure only one of these has been set
int s_c = 0, s_d = 0, s_e = 0, s_r = 0;
/// Checks if switches have been set correctly
void check_switches(void);

int main(int argc, char** argv) {
    // path to keyfile and datafile
    char* keypath, filepath;

    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "cdehn:rv")) != -1)) {
        switch (opt) {
            // Switch -c for creating new key
            case 'c':
                check_switches();
                s_c = 1;
                break;
            // Switch -d for decryption
            case 'd':
                check_switches();
                s_d = 1;
                break;
            // Switch -e for encryption
            case 'e':
                check_switches();
                s_e = 1;
                break;
            // Switch -h for help
            case 'h':
                printf(HELP_STRING);
                exit(EXIT_SUCCESS);
                // Switch -k for help
            case 'n':
                printf("Encrypting data with key %s\n", optarg);
                char* keypath = malloc(strlen(KEYPATH) + strlen(optarg) );
                sprintf(keypath, KEYFILE, optarg);
                if (!fileExists(keypath)) {
                    printf("Error. Key does not exist. Please call create_key first and create a key with the name.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            // Switch -r for renewing a key
            case 'r':
                check_switches();
                s_r = 1;
                verbose = 1;
                break;
            // Switch -v for verbose
            case 'v':
                verbose = 1;
                break;
            default:
                break;
        }
    }
}

void check_switches(void) {
    if (s_c || s_d || s_e || s_r) {
        printf("Error. Please use only one of -c -d -e -r.\n");
        exit(EXIT_FAILURE);
    }
}