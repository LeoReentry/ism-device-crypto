//
// Created by leo on 11/23/16.
//

#include "global.h"
#include <unistd.h>
const char* HELP_STRING = ""
                        "DEVICE ENCRYPTION HELPER\n\n"
                        "This program encrypts and decrypts data using AES-256 in CBC mode. "
                        "For each dataset that's being encrypted, a different encryption key will be used. This Key "
                        "will be bound by the TPM so it will not be usable without a TPM or in a different system "
                        "state. The key will be unbound during an encryption or decryption operation.\n"
                        "This program follows the concept of a dictionary. You can specify a dataset as a dictionary"
                        "key and access the data later with that dictionary key. If you use an existing key, the data"
                        "associated with it will be overwritten.\n"
                        "Usage: deh [OPTIONS] [DATA]\n"
                        "Options:\n"
                        "  -c\tCreate new encryption key. Creates a new AES encryption key\n"
                        "  \twithout encrypting data. If there is data associated to that\n"
                        "  \tkey, that data will be lost forever! If you wish to create a\n"
                        "  \tnew encryption key without losing data, use the option -r.\n"
                        "  -d\tDecryption. Will decrypt the data associated with the given key.\n"
                        "  -e\tEncryption. Will encrypt data passed as argument.\n"
                        "  -h\tHelp. Displays this help.\n"
                        "  -n\tName. This options specifies a name. If no name is given,\n"
                        "  \tit defaults to 'default'\n"
                        "  -r\tRenew encryption key. If no encryption key with the that\n"
                        "  \tname exists, deh will create a new one. If an encryption key\n"
                        "  \twith the name already exists, the data associated to it will\n"
                        "  \tbe decrypted and reencrypted with a newly created key.\n"
                        "  -v\tVerbose. Displays information during the process.\n"
                        "The data must be passed as command line argument.\n"
                        "Examples:\n"
                        "Encrypt data: deh -e -n number 12345\n"
                        "Encrypt data: deh -e -n number 123456\n"
                        "Encrypt data: deh nonamespecified\n"
                        "Encrypt data: deh -e -n text secrettext\n"
                        "Encrypt data: deh -e -n a \"Dataset A\"\n"
                        "Encrypt data: deh -e -n b \"Dataset B\"\n"
                        "Encrypt data: deh -c -n a\n"
                        "Encrypt data: deh -r -n b\n\n"
                        "Decrypt data: deh -d -n number \tRETURNS 123456\n"
                        "Decrypt data: deh -d -n text \tRETURNS secrettext\n"
                        "Decrypt data: deh -d \t\tRETURNS nonamespecified\n"
                        "Decrypt data: deh -d -n default RETURNS nonamespecified\n"
                        "Decrypt data: deh -d -n a \tRETURNS [nonsense]\n"
                        "Decrypt data: deh -d -n b \tRETURNS Dataset B\n"
                        "Input from file: deh -e -n fileInput \"$(< file.txt)\"\n";


int main(int argc, char** argv) {
    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "hk:v")) != -1)) {
        switch (opt) {
            // Switch -h for help
            case 'h':
                printf(HELP_STRING);
                exit(EXIT_SUCCESS);
                // Switch -k for help
            case 'k':
                printf("Encrypting data with key %s\n", optarg);
                char* keypath = malloc(strlen(KEYPATH) + strlen(optarg) );
                sprintf(keypath, KEYFILE, optarg);
                if (!fileExists(keypath)) {
                    printf("Error. Key does not exist. Please call create_key first and create a key with the name.\n");
                    exit(EXIT_FAILURE);
                }
                // Switch -v for verbose
            case 'v':
                verbose = 1;
                break;
            default: break;
        }
    }
}