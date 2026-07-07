#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/aes.h"

#define AES_BLOCK_SIZE 16

// use to convey data
struct args {
    unsigned char *input;
    unsigned char *output;
    unsigned char *key;
};

void *decrypt(void *arg)
{
    // get data
    struct args *targs = (struct args *) arg;
    AES_KEY aes_key;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char input[AES_BLOCK_SIZE];
    unsigned char output[AES_BLOCK_SIZE];
    int i;

    //initial
    memset(input, 0x00, AES_BLOCK_SIZE);
    memset(output, 0x00, AES_BLOCK_SIZE);
    memset(iv, 0x00, AES_BLOCK_SIZE);
    memset(key, 0x00, AES_BLOCK_SIZE);
    memcpy(key, targs->key, strlen(targs->key));

    //open input file
    FILE *fp = fopen(targs->input, "rb");
    if (fp == NULL) {
        printf("Failed to open input file\n");
        exit(1);
    }

    // Open the output file
    FILE *out_file = fopen(targs->output, "wb");
    if (!out_file) {
        printf("Error opening output file %s\n",targs->output);
        fclose(fp);
        exit(1);
    }

    //set key
    if (AES_set_decrypt_key(key, 128, &aes_key) < 0) {
        printf("Failed to set decryption key\n");
        exit(1);
    }
    //decrypt
    while (fread(input, 1, AES_BLOCK_SIZE, fp) == AES_BLOCK_SIZE) {
        AES_cbc_encrypt(input, output, AES_BLOCK_SIZE,
                        &aes_key,
                        iv,
                        AES_DECRYPT);
        fwrite(output,
               1,
               AES_BLOCK_SIZE,
               out_file); // write decrypted data to output file
        memcpy(iv,
               input,
               AES_BLOCK_SIZE); // save last ciphertext block for next iteration
        memset(input,
               0x00,
               AES_BLOCK_SIZE); // clear input buffer after decryption
        memset(output,
               0x00,
               AES_BLOCK_SIZE); // clear output buffer after decryption
    }
    fclose(fp);
    fclose(out_file);
    return 0;
}
#endif