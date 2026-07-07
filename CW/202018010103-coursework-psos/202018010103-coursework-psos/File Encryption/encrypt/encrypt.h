#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>


// function declaration
int scanf_encrypt();
int select_encryption_algorithm(int type);
int confirm_algorithm_choice(int type);
extern int aes_encrypt_file(const char* file_path, const char* out_file, const char* key_string);
extern int aes_decrypt_file(const char* file_path, const char* out_file, const char* key_string);

#endif /* ENCRYPT_H */
