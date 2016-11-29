
#include <openssl/err.h>
#include "global.h"
#include "tpm.h"


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
        "If neither -d nor -e is specified, the program defaults to encryption. If program is in encryption mode, data "
        "MUST be passed. If -n is not specified, the program defaults to the name 'default'. Only one of -cder may be used."
        "\n"
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


int verbose = 0;

void ExitFailure(void) {
    TPM_CloseContext();
    exit(EXIT_FAILURE);
}

void print_info(char* str) {
    if (verbose) {
        printf("%s", str);
    }
}

int fileExists(const char *filename) {
    struct stat st;
    int result = stat(filename, &st);
    return result == 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
