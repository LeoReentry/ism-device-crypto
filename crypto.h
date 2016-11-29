//
// Created by leo on 11/29/16.
//


#ifndef ENC_CRYPTO_H_H
#define ENC_CRYPTO_H_H


void encrypt_data(char* filepath, char* keypath, unsigned char* data);
void decrypt_data(char *filepath, char *keypath, unsigned char** plaintext, int* plaintext_length);
void encrypt_dat(char *name, unsigned char *data);
void decrypt_dat(char *name, unsigned char** plaintext, int* plaintext_length);

#endif //ENC_CRYPTO_H_H
