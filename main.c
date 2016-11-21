#include<stdio.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>

#define FILEPATH "/home/leo/Documents/master/connection_string"
#define KEYPATH "/home/leo/Documents/master/key"

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);

int main(int argc, char **argv) {
    FILE* fout;
    FILE* fin;
    char* data;
    int data_len;

    /* Key and IV */
    unsigned char key[32], iv[16];
    unsigned char newKey[32], newIv[16];
    /* Message to be encrypted */
    unsigned char *plaintext =
            (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Set up key and IV */
    if (!RAND_bytes(key, sizeof key)) {
        /* OpenSSL reports a failure, act accordingly */
    }
    if (!RAND_bytes(iv, sizeof iv)) {
        /* OpenSSL reports a failure, act accordingly */
    }

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);

    fout = fopen(FILEPATH, "wb");
    write(fileno(fout), iv, sizeof iv);
    write(fileno(fout), ciphertext, ciphertext_len);
    fclose(fout);
    fout = fopen(KEYPATH, "wb");
    write(fileno(fout), key, sizeof key);
    fclose(fout);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    printf("IV is:\n");
    BIO_dump_fp (stdout, (const char *)iv, sizeof iv);

    /* Decrypt the ciphertext */
    fin = fopen(FILEPATH, "r");
    fseek(fin, 0, SEEK_END);
    data_len = (int)ftell(fin) - sizeof newIv;
    fseek(fin, 0, SEEK_SET);
    data = (char*)malloc(data_len * sizeof(char));
    if (data) {
        fread (newIv, 1, sizeof newIv, fin);
        fread (data, 1, data_len, fin);
    }
    fclose(fin);

    fin = fopen(KEYPATH, "r");
    if (newKey) {
        fread(newKey, 1, 32, fin);
    }
    fclose(fin);

    decryptedtext_len = decrypt(data, data_len, newKey, newIv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();

    free(data);

}
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}



int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
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
