//
// Created by Yun on 25-5-13.
//
/**
 * @file encrypt.h
 * @brief File encryption program using AES-256 CBC mode encryption
 *
 * This program provides functionality for encrypting files using AES-256 in CBC mode.
 * It includes password-based access control, multi-threaded file processing,
 * key management, and file integrity verification through SHA-256 hashing.
 */
#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <minix/mthread.h>

/* ===== Constants ===== */
/**
 * @brief Macro for standardized error handling
 * @param msg The error message to display before exiting
 */
#define HANDLE_ERRORS(msg) handleErrors(__FILE__, __LINE__, msg)

/**
 * @brief Length of AES-256 encryption key in bytes (256 bits)
 */
#define KEY_LENGTH 32

/**
 * @brief Length of initialization vector in bytes (128 bits)
 */
#define IV_LENGTH 16

/**
 * @brief Size of buffer used for file I/O operations (1 KB)
 */
#define BUFFER_SIZE 1024

/**
 * @brief Size of AES block in bytes (128 bits)
 */
#define AES_BLOCK_SIZE 16

/**
 * @brief Length of SHA-256 hash output in bytes
 */
#define HASH_LENGTH SHA256_DIGEST_LENGTH

/**
 * @brief Filename for storing administrator password hash
 */
#define ADMIN_KEY_FILE "adminKey.bin"

/**
 * @brief Filename for storing encrypted file hash values
 */
#define HASH_VALUE_FILE "HashValue.bin"

/**
 * @brief Filename for storing encrypted filenames and their keys
 */
#define KEY_STORE_FILE "keystore.bin"

/* ===== Data Structures ===== */
/**
 * @brief Thread data structure for parallel encryption processing
 *
 * Contains all necessary information for a thread to perform file encryption
 * independently, including filenames, encryption key and initialization vector.
 */
typedef struct {
 char *input_filename;  /**< Source file to be encrypted */
 char *output_filename; /**< Destination for encrypted content */
 unsigned char key[KEY_LENGTH]; /**< AES-256 encryption key */
 unsigned char iv[IV_LENGTH]; /**< Initialization vector for CBC mode */
} ThreadData;

/* ===== Error Handling Functions ===== */
/**
 * @brief Handles errors by displaying message and terminating program
 *
 * @param file Source file where the error occurred
 * @param line Line number where the error occurred
 * @param msg Error message to display
 */
void handleErrors(const char *file, int line, const char *msg);

/* ===== Hash Calculation Functions ===== */
/**
 * @brief Calculates SHA-256 hash of a string
 *
 * @param str Input string to hash
 * @param len Length of input string
 * @param hash Output buffer for the resulting hash (must be at least HASH_LENGTH bytes)
 */
void sha256(const char *str, size_t len, unsigned char *hash);

/**
 * @brief Calculates SHA-256 hash of a file
 *
 * @param filename Path to file to hash
 * @param hash Output buffer for the resulting hash (must be at least HASH_LENGTH bytes)
 */
void sha256_file(const char *filename, unsigned char *hash);

/* ===== Password Management Functions ===== */
/**
 * @brief Sets administrator password by storing its hash
 *
 * @param password The password to set
 */
void set_password(const char *password);

/**
 * @brief Verifies a password against the stored administrator password hash
 *
 * @param password Password to verify
 * @return 1 if password is correct, 0 otherwise
 */
int verify_password(const char *password);

/* ===== File Operation Functions ===== */
/**
 * @brief Saves hash value of encrypted file for integrity verification
 *
 * @param hash Hash value to save
 * @param filename Name of file to store hash values
 */
void save_hash_to_file(const unsigned char *hash, const char *filename);

/**
 * @brief Saves encryption key associated with a file to the key store
 *
 * @param encrypted_filename Name of the encrypted file
 * @param key Encryption key to store
 */
void save_key_for_file(const char *encrypted_filename, const unsigned char *key);

/**
 * @brief Lists files in current directory that are eligible for encryption
 *
 * @param files Pointer to array of filenames to be allocated and populated
 * @param num_files Pointer to store the number of files found
 */
void list_files_for_encryption(char ***files, int *num_files);

/* ===== Core Encryption Functions ===== */
/**
 * @brief Encrypts a file using AES-256 in CBC mode
 *
 * @param data Thread data structure containing filenames and keys
 */
void encrypt_file(ThreadData *data);

/**
 * @brief Thread function for parallel file encryption
 *
 * @param arg Thread data structure passed as void pointer
 * @return NULL (required by thread API)
 */
void *encrypt_thread_func(void *arg);

/**
 * @brief Encrypts a single file (used in command-line mode)
 *
 * @param input_filename Source file to encrypt
 * @param output_filename Destination for encrypted content
 * @return 0 on success
 */
int encrypt_single_file(const char *input_filename, const char *output_filename);

/* ===== User Interaction Functions ===== */
/**
 * @brief Handles the complete user-interactive encryption process
 */
void process_encryption(void);

/**
 * @brief Displays program usage information
 */
void print_usage(void);

#endif /* ENCRYPT_H */
