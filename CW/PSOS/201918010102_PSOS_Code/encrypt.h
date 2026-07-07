#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/aes.h"

#define AES_BLOCK_SIZE 16

struct args {
    unsigned char *input; // input file path
    unsigned char *key;
};

void *encrypt(void *arg) {
    struct args *args = (struct args*) arg;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    char *output_file = malloc(strlen((const char *)args->input) + 8);
    strcpy(output_file, (const char *)args->input);
    strcat(output_file, ".aes");

    // open input file (read-only)
    FILE *infile = fopen((const char *)args->input, "rb");
    // open output file (write method)
    FILE *outfile = fopen(output_file, "wb");
    if (!infile || !outfile) {
        perror("Error opening file");
        return NULL;
    }

    // set key
    AES_KEY aes_key;
    unsigned char key[AES_BLOCK_SIZE];
    memset(key, 0x00, AES_BLOCK_SIZE);
    memcpy(key, args->key, strlen((const char *)args->key));
    AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    // buffer
    unsigned char input_buf[AES_BLOCK_SIZE], output_buf[AES_BLOCK_SIZE];
    size_t len;
    // initialise
    memset(input_buf, 0x00, sizeof(input_buf));
    memset(output_buf, 0x00, sizeof(output_buf));

    // decrypt (read the file in pieces)
    while ((len = fread(input_buf, 1, AES_BLOCK_SIZE, infile)) > 0) {
        // Padding for the last block
        if (len < AES_BLOCK_SIZE) {
            memset(input_buf + len, 0x00, AES_BLOCK_SIZE - len);
        }
        AES_cbc_encrypt(input_buf, output_buf, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
        fwrite(output_buf, 1, AES_BLOCK_SIZE, outfile);
        // clear buffer after encryption
        memset(input_buf, 0x00, AES_BLOCK_SIZE);
        memset(output_buf, 0x00, AES_BLOCK_SIZE);
    }

    fclose(infile);
    fclose(outfile);
    return 0;
}
#endif
