//
// Created by leo on 11/22/16.
//

#include "global.h"
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "tpm.h"


/// \param ciphertext Ciphertext to be decrypted.
/// \param ciphertext_len Length of ciphertext.
/// \param key Key used for decryption.
/// \param iv Initialization Vector.
/// \param plaintext Resulting plaintext.
/// \return Length of plaintext.
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);


int main(int argc, char** argv) {
    if (!fileExists(KEYPATH)) {
        printf("Error. Couldn't find key file. Please make sure your encryption key is present.\n");
        exit(EXIT_FAILURE);
    }
    if (!fileExists("/home/leo/Documents/master/connectionstring")) {
        printf("Error. Couldn't find the encrypted file. Please make sure your encrypted data is present.\n");
        exit(EXIT_FAILURE);
    }
    // Command line switches
    int opt;
    // Check switches
    while(((opt = getopt(argc, argv, "hv")) != -1)) {
        switch (opt) {
            // Switch -h for help
            case 'h':
                printf("\n\nThis program decrypts data using AES-256 in CBC mode. The encryption key is the key created using create_key. "\
                       "It will be unbound by the TPM for the time of the decryption.\n\n" \
                       "Usage:\n\tdecrypt_data -v data\n" \
                       "\t\t-h\tHelp. Displays this help.\n" \
                       "\t\t-v\tVerbose. Displays information during the process.\n");
                exit(EXIT_SUCCESS);
                // Switch -v for verbose
            case 'v':
                verbose = 1;
                break;
            default: break;
        }
    }

    // Init openSSL library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    // Initialize TPM context
    if (TPM_InitContext())
        ExitFailure();

    // Get data
    unsigned char iv[16];
    int data_len;
    char* data;
    // Read IV and encrypted data from file
    FILE* fin = fopen("/home/leo/Documents/master/connectionstring", "r");
    fseek(fin, 0, SEEK_END);
    data_len = (int)ftell(fin) - sizeof iv;
    fseek(fin, 0, SEEK_SET);
    data = malloc(data_len * sizeof(char));
    if (data) {
        fread (iv, 1, sizeof iv, fin);
        fread (data, 1, data_len, fin);
    }
    else {
        EVP_cleanup();
        ERR_free_strings();
        free(data);
        ExitFailure();
    }
    fclose(fin);

    // GET AES key
    BYTE* key;
    int key_length;
    if(UnbindAESKey(&key, &key_length))
        ExitFailure();
    // Decrypt data
    unsigned char plaintext[data_len];
    int plaintext_len = decrypt((unsigned char*)data, data_len, key, iv, plaintext);
    // Override key
    memset(key, 0, sizeof key);

    plaintext[plaintext_len] = '\0';
    printf("%s\n", plaintext);


    // Close everything
    TPM_CloseContext();
    EVP_cleanup();
    ERR_free_strings();
//    free(key);
    exit(EXIT_SUCCESS);
}




int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * Here, key: 256 bits, IV: 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}