#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/aes.h"

#define AES_BLOCK_SIZE 16

struct args {
    unsigned char *input;
    unsigned char *key;
};

void *encrypt(void *arg) {
    struct args *targs = (struct args *) arg;
    AES_KEY aes_key;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char input[AES_BLOCK_SIZE];
    unsigned char output[AES_BLOCK_SIZE];
    int len;
    //initial
    memset(input, 0x00, sizeof(input));
    memset(output, 0x00, sizeof(output));
    memset(iv, 0x00, AES_BLOCK_SIZE);
    memset(key, 0x00, AES_BLOCK_SIZE);

    //open input file
    FILE *fp = fopen(targs->input, "rb");
    if (fp == NULL) {
        printf("Failed to open input file\n");
        exit(1);
    }

    // Open the output file
    char *output_file = malloc(strlen(targs->input) + 8);
    strcpy(output_file, targs->input);
    strcat(output_file, ".cipher");
    FILE *out_fp = fopen(output_file, "wb");
    if (out_fp == NULL) {
        printf("Failed to open output file\n");
        exit(1);
    }

    //set key
    memcpy(key, targs->key, strlen(targs->key));
    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        printf("Failed to set encryption key\n");
        exit(1);
    }

    //encrypt
    while ((len = fread(input, 1, AES_BLOCK_SIZE, fp)) > 0) {//split
        if(len<AES_BLOCK_SIZE){//padding
            memset(input + len, 0x00, AES_BLOCK_SIZE - len);
        }
        AES_cbc_encrypt(input, output, AES_BLOCK_SIZE, &aes_key,iv,
                        AES_ENCRYPT);
        fwrite(output, 1,
               AES_BLOCK_SIZE,
               out_fp); // write encrypted data to output file
        memset(input, 0x00,
               AES_BLOCK_SIZE); // clear input buffer after encryption
        memset(output, 0x00,
               AES_BLOCK_SIZE); // clear output buffer after encryption
    }

    fclose(fp);
    fclose(out_fp);
    return 0;
}
#endif