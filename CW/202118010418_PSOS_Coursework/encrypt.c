/**
 * @file encrypt.c
 * @brief File encryption program using AES-256 CBC mode encryption
 *
 * This program provides functionality for encrypting files using AES-256 in CBC mode.
 * It includes password-based access control, multi-threaded file processing,
 * key management, and file integrity verification through SHA-256 hashing.
 */

#include "encrypt.h"

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
void handleErrors(const char *file, int line, const char *msg) {
    printf("Error occurred in file %s at line %d: %s\n", file, line, msg);
    exit(1);
}

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
void sha256(const char *str, size_t len, unsigned char *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(hash, &sha256);
}

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
void sha256_file(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        HANDLE_ERRORS("Failed to open file for hashing");
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[BUFFER_SIZE];
    int bytes_read;

    // Process file in chunks to handle large files efficiently
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    SHA256_Final(hash, &sha256);
    fclose(file);
}

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
void set_password(const char *password) {
    unsigned char hash[HASH_LENGTH];
    sha256(password, strlen(password), hash);

    FILE *file = fopen(ADMIN_KEY_FILE, "wb");
    if (!file) {
        HANDLE_ERRORS("Failed to open admin key file for writing");
    }

    fwrite(hash, 1, HASH_LENGTH, file);
    fclose(file);
}

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
int verify_password(const char *password) {
    unsigned char hash[HASH_LENGTH];
    sha256(password, strlen(password), hash);

    FILE *file = fopen(ADMIN_KEY_FILE, "rb");
    if (!file) {
        HANDLE_ERRORS("Failed to open admin key file");
    }

    unsigned char stored_hash[HASH_LENGTH];
    fread(stored_hash, 1, HASH_LENGTH, file);
    fclose(file);

    return memcmp(hash, stored_hash, HASH_LENGTH) == 0;
}

/* ===== File Operation Functions ===== */
/**
 * @brief Saves hash value of encrypted file for integrity verification
 *
 * @param hash Hash value to save
 * @param filename Name of file to store hash values
 *
 * @pre hash must not be NULL
 * @pre filename must be a valid path for file creation
 * @post Hash value will be appended to the specified file in hex format
 * @throws Error if the hash file cannot be opened for writing
 */
void save_hash_to_file(const unsigned char *hash, const char *filename) {
    FILE *file = fopen(filename, "ab");
    if (!file) {
        HANDLE_ERRORS("Failed to open hash value file for writing");
    }

    // Write hash as hex string
    for (int i = 0; i < HASH_LENGTH; i++) {
        fprintf(file, "%02x", hash[i]);
    }
    fprintf(file, "\n");

    fclose(file);
}

/**
 * @brief Saves encryption key associated with a file to the key store
 *
 * @param encrypted_filename Name of the encrypted file
 * @param key Encryption key to store
 *
 * @pre encrypted_filename must not be NULL
 * @pre key must not be NULL
 * @post Key will be saved to the key store file along with the filename
 * @throws Error if the key store file cannot be opened for writing
 */
void save_key_for_file(const char *encrypted_filename, const unsigned char *key) {
    FILE *keystore = fopen(KEY_STORE_FILE, "ab");
    if (!keystore) {
        HANDLE_ERRORS("Failed to open key store file");
    }

    // Write filename length and filename
    size_t filename_len = strlen(encrypted_filename);
    fwrite(&filename_len, sizeof(size_t), 1, keystore);
    fwrite(encrypted_filename, 1, filename_len, keystore);

    // Write encryption key
    fwrite(key, 1, KEY_LENGTH, keystore);

    fclose(keystore);
    printf("Key has been saved to key storage file\n");
}

/**
 * @brief Lists files in current directory that are eligible for encryption
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
void list_files_for_encryption(char ***files, int *num_files) {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (!d) {
        HANDLE_ERRORS("Failed to open current directory");
    }

    *num_files = 0;
    *files = NULL;

    // List all regular files except those already encrypted
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {
            int len = strlen(dir->d_name);
            if (len < 10 || strcmp(dir->d_name + len - 10, ".encrypted") != 0) {
                *files = realloc(*files, (*num_files + 1) * sizeof(char *));
                (*files)[*num_files] = strdup(dir->d_name);
                (*num_files)++;
            }
        }
    }
    closedir(d);
}

/* ===== Core Encryption Functions ===== */
/**
 * @brief Encrypts a file using AES-256 in CBC mode
 *
 * @param data Thread data structure containing filenames and keys
 *
 * @pre data must contain valid input and output filenames
 * @post Input file will be encrypted and written to output file
 * @post Encryption key will be saved to the key store
 * @post File hash will be calculated and saved
 * @throws Error if files cannot be opened, encryption fails, or writing fails
 */
void encrypt_file(ThreadData *data) {
    FILE *input_file = fopen(data->input_filename, "rb");
    FILE *output_file = fopen(data->output_filename, "wb");
    if (!input_file || !output_file) {
        HANDLE_ERRORS("Failed to open input or output file");
    }

    unsigned char iv[IV_LENGTH];
    unsigned char buffer[BUFFER_SIZE];  // Buffer for reading input data
    unsigned char out_buffer[BUFFER_SIZE + AES_BLOCK_SIZE];  // Buffer for encrypted output

    AES_KEY aes_key;

    // Generate a cryptographically secure random key
    unsigned char random_key[KEY_LENGTH];
    if (!RAND_bytes(random_key, KEY_LENGTH)) {
        HANDLE_ERRORS("Failed to generate random key");
    }

    // Store key in thread data
    memcpy(data->key, random_key, KEY_LENGTH);

    // Generate random IV and write to output file
    if (!RAND_bytes(iv, IV_LENGTH)) {
        HANDLE_ERRORS("Failed to generate random IV");
    }
    fwrite(iv, sizeof(unsigned char), IV_LENGTH, output_file);

    // Initialize AES encryption
    if (AES_set_encrypt_key(data->key, 256, &aes_key) < 0) {
        HANDLE_ERRORS("Failed to set encryption key");
    }

    int bytes_read;
    int padding = 0;

    // Process file in chunks
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        if (bytes_read < BUFFER_SIZE) {
            // Add PKCS#7 padding to the last block
            padding = AES_BLOCK_SIZE - (bytes_read % AES_BLOCK_SIZE);
            memset(buffer + bytes_read, padding, padding);
            bytes_read += padding;
        }

        // Encrypt the buffer
        AES_cbc_encrypt(buffer, out_buffer, bytes_read, &aes_key, iv, AES_ENCRYPT);

        // Write encrypted data to output file
        if (fwrite(out_buffer, 1, bytes_read, output_file) != bytes_read) {
            HANDLE_ERRORS("Failed to write to output file");
        }

        // Clear sensitive data from memory
        memset(buffer, 0, sizeof(buffer));
        memset(out_buffer, 0, sizeof(out_buffer));
    }

    // Check for file I/O errors
    if (ferror(input_file) || ferror(output_file)) {
        HANDLE_ERRORS("Error occurred during file read/write");
    }

    fclose(input_file);
    fclose(output_file);

    // Save encryption key to key store
    save_key_for_file(data->output_filename, random_key);

    printf("File '%s' has been successfully encrypted to '%s'.\n", data->input_filename, data->output_filename);

    // Calculate and save file hash for integrity verification
    unsigned char hash[HASH_LENGTH];
    sha256_file(data->output_filename, hash);
    save_hash_to_file(hash, HASH_VALUE_FILE);
}

/**
 * @brief Thread function for parallel file encryption
 *
 * @param arg Thread data structure passed as void pointer
 * @return NULL (required by thread API)
 *
 * @pre arg must be a valid ThreadData pointer
 * @post File will be encrypted using the encrypt_file function
 */
void *encrypt_thread_func(void *arg) {
    ThreadData *data = (ThreadData *) arg;
    encrypt_file(data);
    return NULL;
}

/**
 * @brief Encrypts a single file (used in command-line mode)
 *
 * @param input_filename Source file to encrypt
 * @param output_filename Destination for encrypted content
 * @return 0 on success
 *
 * @pre input_filename must be a valid path to an accessible file
 * @pre output_filename must be a valid path for file creation
 * @post File will be encrypted using the encrypt_file function
 */
int encrypt_single_file(const char *input_filename, const char *output_filename) {
    ThreadData data;
    data.input_filename = (char *)input_filename;
    data.output_filename = (char *)output_filename;

    encrypt_file(&data);
    return 0;
}

/* ===== User Interaction Functions ===== */
/**
 * @brief Handles the complete user-interactive encryption process
 *
 * Lists available files, gets user selection, and initiates multi-threaded
 * encryption of the selected files.
 *
 * @pre None
 * @post Selected files will be encrypted
 */
void process_encryption() {
    char **files;
    int num_files;
    list_files_for_encryption(&files, &num_files);

    if (num_files == 0) {
        printf("No files available for encryption.\n");
        return;
    }

    printf("Files available for encryption:\n");
    for (int i = 0; i < num_files; i++) {
        printf("%d: %s\n", i + 1, files[i]);
    }

    char input[256];
    int selected_files[256];
    int count = 0;

    // Get user file selection with input validation
    while (1) {
        printf("Enter file numbers to encrypt (separated by spaces): ");
        fgets(input, sizeof(input), stdin);

        char *token = strtok(input, " ");
        count = 0;
        int valid_input = 1;

        // Parse space-separated numbers
        while (token != NULL) {
            if (*token == '\n' || *token == '\0') {
                break;
            }
            int index = atoi(token) - 1;
            if (index < 0 || index >= num_files) {
                valid_input = 0;
                break;
            }
            selected_files[count++] = index;
            token = strtok(NULL, " ");
        }

        if (valid_input && count > 0) {
            break;
        } else {
            printf("Invalid input. Please enter valid file numbers separated by spaces.\n");
        }
    }

    // Allocate memory for thread data and threads
    ThreadData *data = malloc(count * sizeof(ThreadData));
    mthread_thread_t *threads = malloc(count * sizeof(mthread_thread_t));

    // Create and launch encryption threads
    for (int i = 0; i < count; i++) {
        int index = selected_files[i];
        data[i].input_filename = files[index];
        data[i].output_filename = malloc(strlen(files[index]) + 11);  // 11 for ".encrypted" + null
        snprintf(data[i].output_filename, strlen(files[index]) + 11, "%s.encrypted", files[index]);

        if (mthread_create(&threads[i], NULL, encrypt_thread_func, &data[i]) != 0) {
            HANDLE_ERRORS("Failed to create thread");
        }
    }

    // Wait for all threads to complete
    for (int i = 0; i < count; i++) {
        if (mthread_join(threads[i], NULL) != 0) {
            HANDLE_ERRORS("Failed to join thread");
        }
        free(data[i].output_filename);
    }

    // Clean up allocated resources
    free(data);
    free(threads);

    for (int i = 0; i < num_files; i++) {
        free(files[i]);
    }
    free(files);
}

/**
 * @brief Displays program usage information
 */
void print_usage() {
    printf("Usage:\n");
    printf("  ./encrypt                        - Interactive mode\n");
    printf("  ./encrypt input.txt output.txt   - Command line mode\n");
    printf("  ./encrypt --help                 - Display this help information\n");
}

/* ===== Main Function ===== */
/**
 * @brief Program entry point
 *
 * Handles command-line arguments, password verification, and
 * launches either interactive or command-line encryption mode.
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on success, 1 on error
 */
int main(int argc, char *argv[]) {
    // Process command-line arguments
    if (argc > 1) {
        // Help information request
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage();
            return 0;
        }

        // Command-line encryption mode
        if (argc == 3) {
            // Verify administrator password
            FILE *admin_key_file = fopen(ADMIN_KEY_FILE, "rb");
            if (!admin_key_file) {
                // First-time setup - create admin password
                printf("First use, please set administrator password: ");
                char password[256];
                scanf("%255s", password);
                set_password(password);
                printf("Password set successfully.\n");
            } else {
                // Verify existing password
                fclose(admin_key_file);
                char password[256];
                printf("Please enter administrator password: ");
                scanf("%255s", password);
                if (!verify_password(password)) {
                    printf("Incorrect password. Exiting.\n");
                    return 1;
                }
                printf("Password verification successful. Access granted.\n");
            }

            // Perform single file encryption
            return encrypt_single_file(argv[1], argv[2]);
        } else if (argc != 1) {
            // Invalid argument count
            printf("Invalid number of arguments.\n");
            print_usage();
            return 1;
        }
    }

    // Interactive mode
    // Verify or create administrator password
    FILE *admin_key_file = fopen(ADMIN_KEY_FILE, "rb");
    if (admin_key_file) {
        // Check if file exists but is empty
        fseek(admin_key_file, 0, SEEK_END);
        long file_size = ftell(admin_key_file);
        fclose(admin_key_file);

        if (file_size == 0) {
            // Empty file - prompt for new password
            char password[256];
            printf("Set new administrator password: ");
            scanf("%255s", password);
            set_password(password);
            printf("Password set successfully.\n");
        } else {
            // File exists with password - verify
            while (1) {
                char password[256];
                printf("Please enter administrator password: ");
                scanf("%255s", password);
                if (verify_password(password)) {
                    printf("Password verification successful. Access granted.\n");
                    break;
                } else {
                    printf("Incorrect password. Please try again.\n");
                }
            }
        }
    } else {
        // File doesn't exist - first time use
        char password[256];
        printf("Set new administrator password: ");
        scanf("%255s", password);
        set_password(password);
        printf("Password set successfully.\n");
    }

    // Clear input buffer before interactive mode
    while (getchar() != '\n');

    printf("=== File Encryption Program ===\n");
    process_encryption();

    return 0;
}