#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/aes.h"

#define AES_BLOCK_SIZE 16

struct args {
    unsigned char *input; // input file path
    unsigned char *output; // output file path
    unsigned char *key;
} ;

void *decrypt(void *arg){
    struct args *args = (struct args *) arg;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    // open input file (read-only)
    FILE *infile = fopen((const char *)args->input, "rb");
    // open output file (write method)
    FILE *outfile = fopen((const char *)args->output, "wb");
    if (!infile || !outfile) {
        perror("Error opening file");
        return NULL;
    }

    AES_KEY aes_key;
    unsigned char key[AES_BLOCK_SIZE];
    memset(key, 0x00, AES_BLOCK_SIZE);
    memcpy(key, args->key, strlen((const char *)args->key));
    AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);

    // buffer
    unsigned char input_buf[AES_BLOCK_SIZE], output_buf[AES_BLOCK_SIZE];
    // initialise
    memset(input_buf, 0x00, AES_BLOCK_SIZE);
    memset(output_buf, 0x00, AES_BLOCK_SIZE);

    // decrypt
    while (fread(input_buf, 1, AES_BLOCK_SIZE, infile) == AES_BLOCK_SIZE) {
        AES_cbc_encrypt(input_buf, output_buf, AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);
        fwrite(output_buf, 1, AES_BLOCK_SIZE, outfile);
        memcpy(iv, input_buf, AES_BLOCK_SIZE); // save last ciphertext block
        // clear buffer after decryption
        memset(input_buf, 0x00, AES_BLOCK_SIZE);
        memset(output_buf, 0x00, AES_BLOCK_SIZE);
    }

    fclose(infile);
    fclose(outfile);
    return 0;
}
#endif
