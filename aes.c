//
// Created by leo on 11/23/16.
//
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>
#include "aes.h"
#include "global.h"

/// Function that encrypts the data.
/// \param plaintext Plaintext to be encrypted.
/// \param plaintext_len Length of plaintext.
/// \param key Key used for encryption.
/// \param iv Initialization Vector used for encryption.
/// \param ciphertext Resulting ciphertext.
/// \return Length of ciphertext.
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
/// \param ciphertext Ciphertext to be decrypted.
/// \param ciphertext_len Length of ciphertext.
/// \param key Key used for decryption.
/// \param iv Initialization Vector.
/// \param plaintext Resulting plaintext.
/// \return Length of plaintext.
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

int AES_CreateKey(unsigned char *key) {
    print_info("Creating new AES key... ");
    fflush(stdout);
    if (!RAND_bytes(key, KEY_SIZE)) {
        // Minimum of 120 byte when using error string
        char *err = malloc(120*sizeof(char));
        ERR_error_string(ERR_get_error(), err);
        printf("Error during AES key creation: %s\n", err);
        free(err);
        return 1;
    }
    print_info("Success.\n");
    return 0;
}
int AES_EncryptData(unsigned char* plaintext, unsigned char* key, char* filepath) {
    // Init openSSL library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    // Encrypt data
    // Variables
    int ciphertext_len;
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
    int check_len = encrypt (plaintext, (int)strlen ((char *)plaintext), key, iv, ciphertext);

    // If data isn't as long as we calculated, something went wrong
    if (check_len != ciphertext_len) {
        memset(key, 0, KEY_SIZE);
        printf("Encryption error.\n");
        EVP_cleanup();
        ERR_free_strings();
        free(ciphertext);
        return 1;
    }
    print_info("Success.\n");
    // Ok, now we can save the encrypted data + IV to file
    FILE* fout = fopen(filepath, "wb");
    write(fileno(fout), iv, sizeof iv);
    write(fileno(fout), ciphertext, (size_t)ciphertext_len);
    fclose(fout);
    // Close all relevant stuff
    EVP_cleanup();
    ERR_free_strings();
    free(ciphertext);
    return 0;
}
int AES_DecryptData(unsigned char** plaintext, unsigned char* key, char* filepath, int* length) {
    // Init openSSL library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    print_info("Reading data from file...");
    fflush(stdout);
    // Get data
    unsigned char iv[16];
    int data_len;
    char* data;
    // Read IV and encrypted data from file
    FILE* fin = fopen(filepath, "r");
    fseek(fin, 0, SEEK_END);
    data_len = (int)ftell(fin) - sizeof iv;
    fseek(fin, 0, SEEK_SET);
    data = malloc(data_len * sizeof(char));
    if (data) {
        fread (iv, 1, sizeof iv, fin);
        fread (data, 1, data_len, fin);
    }
    else {
        memset(key, 0, KEY_SIZE);
        EVP_cleanup();
        ERR_free_strings();
        free(data);
        return 1;
    }
    fclose(fin);
    print_info("Done.\n");
    *plaintext = malloc(data_len * sizeof(unsigned char));
    // Decrypt data
    int plaintext_len = decrypt((unsigned char*)data, data_len, key, iv, *plaintext);
    // Override key
    memset(key, 0, KEY_SIZE);
    // Add null terminator
    (*plaintext)[plaintext_len] = '\0';
    *length = plaintext_len;
    EVP_cleanup();
    ERR_free_strings();
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