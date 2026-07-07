#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>  // For strlen
#include <stdio.h>   // For FILE operations and fprintf
#include <stdlib.h>  // For exit

#define ITERATIONS 100000  // Number of iterations for PBKDF2
#define SALT_SIZE 8        // Size of the salt in bytes
#define IV_SIZE 16         // Size of the initialization vector in bytes

/**
 * Handle encryption/decryption errors
 * Prints an error message and exits the program
 */
void handle_errors() {
    fprintf(stderr, "Encryption/Decryption error\n");
    exit(1);
}

/**
 * Derive encryption key using PBKDF2
 *
 * @param password The user-provided password
 * @param salt Random salt for key derivation
 * @param key Output buffer for the derived key
 * @param iv Output buffer for the initialization vector
 */
void derive_key(const char* password, const unsigned char* salt, unsigned char* key, unsigned char* iv) {
    if (PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        salt, SALT_SIZE,
        ITERATIONS,
        EVP_sha256(),
        32 + IV_SIZE,  // Length of key + IV
        key            // Output buffer
    ) != 1) handle_errors();
}

/**
 * Encrypt a file using AES-256-CTR mode
 *
 * @param input_path Path to the input file to be encrypted
 * @param output_path Path where the encrypted file will be saved
 * @param password User-provided password for encryption
 */
void encrypt_file(const char* input_path, const char* output_path, const char* password) {
    unsigned char salt[SALT_SIZE], iv[IV_SIZE];
    RAND_bytes(salt, SALT_SIZE);  // Generate random salt
    RAND_bytes(iv, IV_SIZE);      // Generate random IV

    unsigned char key[32 + IV_SIZE];
    derive_key(password, salt, key, key + 32);  // Derive key and IV

    // Initialize encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
        handle_errors();

    // Open input and output files
    FILE* fin = fopen(input_path, "rb");
    FILE* fout = fopen(output_path, "wb");
    fwrite(salt, 1, SALT_SIZE, fout);  // Write salt to output
    fwrite(iv, 1, IV_SIZE, fout);      // Write IV to output

    // Process file in chunks
    unsigned char in_buf[1024], out_buf[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;
    while ((bytes_read = fread(in_buf, 1, 1024, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) != 1)
            handle_errors();
        fwrite(out_buf, 1, out_len, fout);
    }

    // Process final block
    if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1)
        handle_errors();
    fwrite(out_buf, 1, out_len, fout);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);

    // Securely zero the key material from memory
    OPENSSL_cleanse(key, sizeof(key));  // Replaced explicit_bzero with OPENSSL_cleanse
}

/**
 * Decrypt a file using AES-256-CTR mode
 *
 * @param input_path Path to the encrypted input file
 * @param output_path Path where the decrypted file will be saved
 * @param password User-provided password for decryption
 */
void decrypt_file(const char* input_path, const char* output_path, const char* password) {
    // Read salt and IV from encrypted file header
    unsigned char salt[SALT_SIZE], iv[IV_SIZE];

    FILE* fin = fopen(input_path, "rb");
    FILE* fout = fopen(output_path, "wb");

    if (!fin || !fout) handle_errors();

    // Read salt and IV from file header
    if (fread(salt, 1, SALT_SIZE, fin) != SALT_SIZE ||
        fread(iv, 1, IV_SIZE, fin) != IV_SIZE) {
        handle_errors();
        }

    // Derive the same key using password and salt
    unsigned char key[32 + IV_SIZE];
    derive_key(password, salt, key, key + 32);

    // Initialize decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
        handle_errors();

    // Process file in chunks
    unsigned char in_buf[1024], out_buf[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;
    while ((bytes_read = fread(in_buf, 1, 1024, fin)) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) != 1)
            handle_errors();
        fwrite(out_buf, 1, out_len, fout);
    }

    // Process final block
    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) != 1)
        handle_errors();
    fwrite(out_buf, 1, out_len, fout);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);

    // Securely zero the key material from memory
    OPENSSL_cleanse(key, sizeof(key));
}