#define _GNU_SOURCE
#include <stdio.h>
#include "global.h"
#include <unistd.h>

/// Checks if exclusive switches have been set correctly
void check_switches(int es);

int main(int argc, char** argv) {
    // Variable to check exclusive switches
    int exclusive_switch = 0;
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
                asprintf(&keypath, KEY_FILE, dir_path, optarg);
                asprintf(&filepath, DATA_FILE, dir_path, optarg);
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
    if (!exclusive_switch) {
        encryption = 1;
    }
}

void check_switches(int es) {
    if (es) {
        printf("Error. Please use only one of -c -d -e -r.\n");
        exit(EXIT_FAILURE);
    }
}