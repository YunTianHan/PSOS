#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <minix/mthread.h>
#include <dirent.h>

#define AES_KEYLEN 32 // 256位
#define AES_BLOCK_SIZE 16

void sha256(const char *password, unsigned char *key) {
    SHA256((const unsigned char *)password, strlen(password), key);
}

int aes_encrypt_file(const char *infile, const char *outfile, const char *password) {
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout) return -1;

    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_BLOCK_SIZE];
    sha256(password, key);
    RAND_bytes(iv, AES_BLOCK_SIZE);
    fwrite(iv, 1, AES_BLOCK_SIZE, fout);

    AES_KEY enc_key;
    AES_set_encrypt_key(key, 256, &enc_key);

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;
    while ((inlen = fread(inbuf, 1, 1024, fin)) > 0) {
        if (inlen % AES_BLOCK_SIZE != 0) {
            int pad = AES_BLOCK_SIZE - (inlen % AES_BLOCK_SIZE);
            memset(inbuf + inlen, pad, pad);
            inlen += pad;
        }
        AES_cbc_encrypt(inbuf, outbuf, inlen, &enc_key, iv, AES_ENCRYPT);
        fwrite(outbuf, 1, inlen, fout);
    }
    fclose(fin);
    fclose(fout);
    return 0;
}

int aes_decrypt_file(const char *infile, const char *outfile, const char *password) {
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout) return -1;

    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_BLOCK_SIZE];
    sha256(password, key);
    fread(iv, 1, AES_BLOCK_SIZE, fin);

    AES_KEY dec_key;
    AES_set_decrypt_key(key, 256, &dec_key);

    unsigned char inbuf[1040], outbuf[1040];
    int inlen;
    while ((inlen = fread(inbuf, 1, 1024, fin)) > 0) {
        AES_cbc_encrypt(inbuf, outbuf, inlen, &dec_key, iv, AES_DECRYPT);
        // 去除填充
        if (feof(fin)) {
            int pad = outbuf[inlen - 1];
            fwrite(outbuf, 1, inlen - pad, fout);
        } else {
            fwrite(outbuf, 1, inlen, fout);
        }
    }
    fclose(fin);
    fclose(fout);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s [enc|dec] input_file output_file password\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "enc") == 0) {
        return aes_encrypt_file(argv[2], argv[3], argv[4]);
    } else if (strcmp(argv[1], "dec") == 0) {
        return aes_decrypt_file(argv[2], argv[3], argv[4]);
    } else {
        printf("Unknown operation: %s\n", argv[1]);
        return 1;
    }
}
