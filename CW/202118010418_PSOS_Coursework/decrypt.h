//
// Created by Yun on 25-5-13.
//
/**
 * @file decrypt.h
 * @brief File decryption program using AES-256 CBC mode decryption
 *
 * This program provides functionality for decrypting files previously encrypted
 * with the encrypt.c program. It uses AES-256 in CBC mode, validates file
 * integrity using SHA-256 hashing, and handles key retrieval from a central key store.
 * The program supports both interactive and command-line modes of operation.
 */
#ifndef DECRYPT_H
#define DECRYPT_H

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
 * @brief Thread data structure for parallel decryption processing
 *
 * Contains all necessary information for a thread to perform file decryption
 * independently, including filenames, encryption key and initialization vector.
 */
typedef struct {
    char *input_filename;  /**< Source encrypted file */
    char *output_filename; /**< Destination for decrypted content */
    unsigned char key[KEY_LENGTH]; /**< AES-256 decryption key */
    unsigned char iv[IV_LENGTH]; /**< Initialization vector for CBC mode */
} ThreadData;

/* ===== Error Handling Functions ===== */
/**
 * @brief Handles errors by displaying message and terminating program
 *
 * @param file Source file where the error occurred
 * @param line Line number where the error occurred
 * @param msg Error message to display
 *
 * @pre Parameters must not be NULL
 * @post Program will terminate with exit code 1
 */
void handleErrors(const char *file, int line, const char *msg);

/* ===== Hash Calculation Functions ===== */
/**
 * @brief Calculates SHA-256 hash of a string
 *
 * @param str Input string to hash
 * @param len Length of input string
 * @param hash Output buffer for the resulting hash (must be at least HASH_LENGTH bytes)
 *
 * @pre str must not be NULL
 * @pre hash must be allocated with at least HASH_LENGTH bytes
 * @post hash will contain the SHA-256 digest of the input string
 */
void sha256(const char *str, size_t len, unsigned char *hash);

/**
 * @brief Calculates SHA-256 hash of a file
 *
 * @param filename Path to file to hash
 * @param hash Output buffer for the resulting hash (must be at least HASH_LENGTH bytes)
 *
 * @pre filename must be a valid path to an accessible file
 * @pre hash must be allocated with at least HASH_LENGTH bytes
 * @post hash will contain the SHA-256 digest of the file contents
 * @throws Error if file cannot be opened or read
 */
void sha256_file(const char *filename, unsigned char *hash);

/* ===== Password Management Functions ===== */
/**
 * @brief Sets administrator password by storing its hash
 *
 * @param password The password to set
 *
 * @pre password must not be NULL
 * @post The hashed password will be stored in ADMIN_KEY_FILE
 * @throws Error if the key file cannot be opened for writing
 */
void set_password(const char *password);

/**
 * @brief Verifies a password against the stored administrator password hash
 *
 * @param password Password to verify
 * @return 1 if password is correct, 0 otherwise
 *
 * @pre password must not be NULL
 * @pre ADMIN_KEY_FILE must exist and contain a valid hash
 * @throws Error if the key file cannot be opened for reading
 */
int verify_password(const char *password);

/* ===== Key Management Functions ===== */
/**
 * @brief Retrieves encryption key for a specific file from key store
 *
 * @param encrypted_filename Name of the encrypted file
 * @param key Buffer to store the retrieved key (must be at least KEY_LENGTH bytes)
 * @return 1 if key was found, 0 otherwise
 *
 * @pre encrypted_filename must not be NULL
 * @pre key must be allocated with at least KEY_LENGTH bytes
 * @post key will contain the encryption key if found
 * @throws Error if the key store file cannot be opened for reading
 */
int get_key_for_file(const char *encrypted_filename, unsigned char *key);

/* ===== File Operation Functions ===== */
/**
 * @brief Verifies if a file hash matches a previously stored hash
 *
 * @param filename Name of the file to verify
 * @param hash Hash value of the file
 * @return 1 if hash matches, 0 otherwise
 *
 * @pre filename must not be NULL
 * @pre hash must not be NULL
 * @post None
 * @throws Error if the hash file cannot be opened for reading
 */
int verify_file_hash(const char *filename, const unsigned char *hash);

/**
 * @brief Lists files in current directory that are eligible for decryption
 *
 * @param files Pointer to array of filenames to be allocated and populated
 * @param num_files Pointer to store the number of files found
 *
 * @pre files must be a valid pointer to char**
 * @pre num_files must be a valid pointer to int
 * @post files will contain an array of dynamically allocated strings with filenames
 * @post num_files will contain the number of files found
 * @post The caller is responsible for freeing the allocated memory
 * @throws Error if the directory cannot be opened
 */
void list_files_for_decryption(char ***files, int *num_files);

/* ===== Core Decryption Functions ===== */
/**
 * @brief Decrypts a file using AES-256 in CBC mode
 *
 * @param data Thread data structure containing filenames and keys
 *
 * @pre data must contain valid input and output filenames
 * @post Input file will be decrypted and written to output file
 * @throws Error if files cannot be opened, decryption fails, or writing fails
 */
void decrypt_file(ThreadData *data);

/**
 * @brief Thread function for parallel file decryption
 *
 * @param arg Thread data structure passed as void pointer
 * @return NULL (required by thread API)
 *
 * @pre arg must be a valid ThreadData pointer
 * @post File will be decrypted using the decrypt_file function
 */
void *decrypt_thread_func(void *arg);

/**
 * @brief Decrypts a single file (used in command-line mode)
 *
 * @param input_filename Source encrypted file
 * @param output_filename Destination for decrypted content
 * @return 0 on success
 *
 * @pre input_filename must be a valid path to an accessible encrypted file
 * @pre output_filename must be a valid path for file creation
 * @post File will be decrypted using the decrypt_file function
 */
int decrypt_single_file(const char *input_filename, const char *output_filename);

/* ===== User Interaction Functions ===== */
/**
 * @brief Handles the complete user-interactive decryption process
 *
 * Lists available encrypted files, gets user selection, and initiates
 * multi-threaded decryption of the selected files.
 *
 * @pre None
 * @post Selected files will be decrypted
 */
void process_decryption(void);

/**
 * @brief Displays program usage information
 */
void print_usage(void);

#endif /* DECRYPT_H */
