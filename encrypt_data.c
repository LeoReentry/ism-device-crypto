//
// Created by leo on 11/22/16.
//

#include "global.h"
#include "tpm.h"
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define HELP_STRING     "\n\nThis program encrypts data using AES-256 in CBC mode. The encryption key is the key created using create_key. "\
                        "It will be unbound by the TPM for the time of the encryption and then be bound again.\n\n" \
                        "Usage:\n"\
                        "\tencrypt_data -v data\n" \
                        "\t\t-h\tHelp. Displays this help.\n" \
                        "\t\t-v\tVerbose. Displays information during the process.\n" \
                        "\tThe data must be passed as command line argument.\n"

/// Decrypts AES key from file to memory.
/// \param key Buffer in which key is written. Memory allocated by function.
/// \param length Length of key. Is set by function.
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int UnbindAESKey(BYTE** key, int* length);
/// Function that encrypts the data.
/// \param plaintext Plaintext to be encrypted.
/// \param plaintext_len Length of plaintext.
/// \param key Key used for encryption.
/// \param iv Initialization Vector used for encryption.
/// \param ciphertext Resulting ciphertext.
/// \return Length of ciphertext.
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);


int main(int argc, char** argv) {
    if (!fileExists(KEYPATH)) {
        printf("Error. Couldn't find key file. Please make sure your encryption key is present.\n");
        exit(EXIT_FAILURE);
    }
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

    // Check that we have an additional argument
    if (!(argc-optind)){
        printf(HELP_STRING);
        exit(EXIT_FAILURE);
    }

    // Init openSSL library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    // Initialize TPM context
    if (TPM_InitContext())
        ExitFailure();

    // GET AES key
    BYTE* key;
    int key_length;
    if(UnbindAESKey(&key, &key_length))
        ExitFailure();

    // Encrypt data
    // Variables
    int ciphertext_len;
    unsigned char* plaintext = (unsigned char*)argv[optind];
    unsigned char iv[16];
    print_info("Generating IV... ");
    fflush(stdout);
    // Generate Initialization Vector
    if (!RAND_bytes(iv, sizeof iv)) {
        // Minimum of 120 byte when using error string
        char *err = malloc(120*sizeof(char));
        ERR_error_string(ERR_get_error(), err);
        printf("Error during IV creation: %s\n", err);
        free(err);
        return 1;
    }
    print_info("Success.\nEncrypting data... ");
    fflush(stdout);
    // Calculate ciphertext length
    ciphertext_len = (int)(strlen((char*)plaintext)/16 + 1) * 16;
    // Allocate memory
    unsigned char *ciphertext = malloc(ciphertext_len * sizeof(char));
    // Encrypt data
    int check_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);
    // Clear key memory
    memset(key, 0, sizeof key);
    // If data isn't as long as we calculated, something went wrong
    if (check_len != ciphertext_len) {
        printf("Encryption error.\n");
        TPM_CloseContext();
        EVP_cleanup();
        ERR_free_strings();
        free(ciphertext);
        free(key);
        exit(EXIT_FAILURE);
    }
    print_info("Success.\n");

    // Ok, now we can save the encrypted data + IV to file
    FILE* fout = fopen("/home/leo/Documents/master/connectionstring", "wb");
    write(fileno(fout), iv, sizeof iv);
    write(fileno(fout), ciphertext, ciphertext_len);
    fclose(fout);

    // Close everything
    TPM_CloseContext();
    EVP_cleanup();
    ERR_free_strings();
    free(ciphertext);
    free(key);
    exit(EXIT_SUCCESS);
}


int UnbindAESKey(BYTE** key, int* length) {
    // TPM variables
    TSS_HKEY hBindKey = 0;
    TSS_UUID BindKey_UUID = KEY_UUID;
    TSS_HOBJECT hEncData = 0;
    TSS_HPOLICY hBindKeyPolicy = 0;
    // Encrypted data
    FILE *fin;
    UINT32 encKeyLength;
    BYTE *encKey;
    // Unencrypted key
    UINT32 keyLength;

    print_info("Reading AES key from file... ");
    fflush(stdout);
    // Read encrypted data from file
    fin = fopen(KEYPATH, "r");
    fseek(fin, 0, SEEK_END);
    encKeyLength = (uint32_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);
    encKey = (BYTE*)malloc(encKeyLength*sizeof(BYTE));
    if (encKey) {
        fread (encKey, 1, encKeyLength, fin);
    }
    fclose(fin);
    print_info("Success.\nUnbinding AES key... ");
    fflush(stdout);

    // Get key
    result = Tspi_Context_GetKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, BindKey_UUID, &hBindKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Get key by UUID. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Load the key with wrapping key
    result = Tspi_Key_LoadKey(hBindKey, hSRK);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Load key. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Get policy
    result = Tspi_GetPolicyObject(hBindKey, TSS_POLICY_USAGE, &hBindKeyPolicy);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Get key policy. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Set policy secret
    Tspi_Policy_SetSecret( hBindKeyPolicy, TSS_SECRET_MODE_PLAIN, 20, wks  );
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Set key secret. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }
    // Create data object.
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Create data object. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Feed encrypted data into data object.
    result = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, encKeyLength, encKey);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Feed encrypted data into object. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    // Unbind data
    result = Tspi_Data_Unbind(hEncData, hBindKey, &keyLength, key);
    if(result != TSS_SUCCESS) {
        TPM_CloseContext();
        printf("Error during data unbinding: Unbind data. Error 0x%08x:%s\n", result, Trspi_Error_String(result));
        return 1;
    }

    print_info("Success.\n");
    free(encKey);
    *length = keyLength;
    // Close handles
    Tspi_Key_UnloadKey(hBindKey);
    Tspi_Context_CloseObject(hContext, hBindKeyPolicy);
    Tspi_Context_CloseObject(hContext, hEncData);
    Tspi_Context_CloseObject(hContext, hBindKey);
    return 0;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    // Create and init the context
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * Here, key: 256 bits, IV: 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}