#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <minix/mthread.h>
#include <dirent.h>

#define KEY_LENGTH 32
#define IV_LENGTH 16
#define BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH
#define ADMIN_KEY_FILE "adminKey.bin"
#define HASH_VALUE_FILE "HashValue.bin"

// 线程数据
typedef struct {
    const char *input_filename;
    const char *output_filename;
    unsigned char key[KEY_LENGTH];
    unsigned char iv[IV_LENGTH];
} ThreadData;

// 通用工具
void handleErrors(const char *file, int line, const char *msg);
void sha256_file(const char *filename, unsigned char *hash);
void save_hash_to_file(const unsigned char *hash, const char *filename);
int hash_in_file(const unsigned char *hash, const char *filename);
int verify_password(const char *password);
void set_password(const char *password);

#endif // COMMON_H

