/**
 * @file decrypt.c
 * @brief File decryption program using AES-256 CBC mode decryption
 *
 * This program provides functionality for decrypting files previously encrypted
 * with the encrypt.c program. It uses AES-256 in CBC mode, validates file
 * integrity using SHA-256 hashing, and handles key retrieval from a central key store.
 * The program supports both interactive and command-line modes of operation.
 */

# include "decrypt.h"

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
int get_key_for_file(const char *encrypted_filename, unsigned char *key) {
    FILE *keystore = fopen(KEY_STORE_FILE, "rb");
    if (!keystore) {
        HANDLE_ERRORS("Failed to open key store file for reading");
    }

    int found = 0;
    size_t filename_len;
    char *stored_filename;

    // Read entries until we find a match or reach end of file
    while (fread(&filename_len, sizeof(size_t), 1, keystore) == 1) {
        stored_filename = (char *)malloc(filename_len + 1);
        if (!stored_filename) {
            HANDLE_ERRORS("Memory allocation failed");
        }

        // Read filename and key
        if (fread(stored_filename, 1, filename_len, keystore) != filename_len) {
            free(stored_filename);
            break;
        }
        stored_filename[filename_len] = '\0';

        // Check if this is the file we're looking for
        if (strcmp(stored_filename, encrypted_filename) == 0) {
            if (fread(key, 1, KEY_LENGTH, keystore) == KEY_LENGTH) {
                found = 1;
            }
            free(stored_filename);
            break;
        }

        // Not a match, skip the key and continue
        free(stored_filename);
        fseek(keystore, KEY_LENGTH, SEEK_CUR);
    }

    fclose(keystore);
    return found;
}

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
int verify_file_hash(const char *filename, const unsigned char *hash) {
    FILE *file = fopen(HASH_VALUE_FILE, "rb");
    if (!file) {
        // No hash file means we can't verify, but we'll continue
        return 1;
    }

    char line[HASH_LENGTH * 2 + 1];  // Each byte is 2 hex chars
    unsigned char file_hash[HASH_LENGTH];
    int match = 0;

    // Read hash entries line by line
    while (fgets(line, sizeof(line), file) != NULL) {
        line[HASH_LENGTH * 2] = '\0';  // Ensure null termination

        // Convert hex string to binary
        for (int i = 0; i < HASH_LENGTH; i++) {
            sscanf(&line[i * 2], "%2hhx", &file_hash[i]);
        }

        // Compare with our hash
        if (memcmp(hash, file_hash, HASH_LENGTH) == 0) {
            match = 1;
            break;
        }
    }

    fclose(file);
    return match;
}

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
void list_files_for_decryption(char ***files, int *num_files) {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (!d) {
        HANDLE_ERRORS("Failed to open current directory");
    }

    *num_files = 0;
    *files = NULL;

    // List all files with the .encrypted extension
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {
            int len = strlen(dir->d_name);
            if (len >= 10 && strcmp(dir->d_name + len - 10, ".encrypted") == 0) {
                *files = realloc(*files, (*num_files + 1) * sizeof(char *));
                (*files)[*num_files] = strdup(dir->d_name);
                (*num_files)++;
            }
        }
    }
    closedir(d);
}

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
void decrypt_file(ThreadData *data) {
    FILE *input_file = fopen(data->input_filename, "rb");
    FILE *output_file = fopen(data->output_filename, "wb");
    if (!input_file || !output_file) {
        HANDLE_ERRORS("Failed to open input or output file");
    }

    // Retrieve the key from the key store
    if (!get_key_for_file(data->input_filename, data->key)) {
        fclose(input_file);
        fclose(output_file);
        HANDLE_ERRORS("Could not find decryption key for this file");
    }

    // Read the IV from the beginning of the encrypted file
    if (fread(data->iv, 1, IV_LENGTH, input_file) != IV_LENGTH) {
        fclose(input_file);
        fclose(output_file);
        HANDLE_ERRORS("Failed to read initialization vector from encrypted file");
    }

    unsigned char buffer[BUFFER_SIZE + AES_BLOCK_SIZE];  // Buffer for reading encrypted data
    unsigned char out_buffer[BUFFER_SIZE + AES_BLOCK_SIZE];  // Buffer for decrypted output

    AES_KEY aes_key;

    // Initialize AES decryption
    if (AES_set_decrypt_key(data->key, 256, &aes_key) < 0) {
        HANDLE_ERRORS("Failed to set decryption key");
    }

    // Process file in chunks
    unsigned char iv_copy[IV_LENGTH];
    memcpy(iv_copy, data->iv, IV_LENGTH);  // Make a copy as AES_cbc_encrypt modifies IV

    int bytes_read;
    size_t total_size = 0;
    long file_size;

    // Get file size for padding removal
    fseek(input_file, 0, SEEK_END);
    file_size = ftell(input_file) - IV_LENGTH;  // Subtract IV length
    fseek(input_file, IV_LENGTH, SEEK_SET);     // Reset to start of encrypted data

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        // Decrypt the buffer
        AES_cbc_encrypt(buffer, out_buffer, bytes_read, &aes_key, iv_copy, AES_DECRYPT);

        // For the last block, we need to handle padding
        if (total_size + bytes_read >= file_size) {
            // This is the last block, check for padding
            int padding = out_buffer[bytes_read - 1];

            // Validate padding (PKCS#7)
            if (padding > 0 && padding <= AES_BLOCK_SIZE) {
                // Make sure all padding bytes have the same value
                int valid_padding = 1;
                for (int i = bytes_read - padding; i < bytes_read - 1; i++) {
                    if (out_buffer[i] != padding) {
                        valid_padding = 0;
                        break;
                    }
                }

                if (valid_padding) {
                    // Remove padding
                    bytes_read -= padding;
                }
            }
        }

        // Write decrypted data to output file
        if (bytes_read > 0) {
            if (fwrite(out_buffer, 1, bytes_read, output_file) != bytes_read) {
                HANDLE_ERRORS("Failed to write to output file");
            }
        }

        total_size += bytes_read;

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

    printf("File '%s' has been successfully decrypted to '%s'.\n",
           data->input_filename, data->output_filename);
}

/**
 * @brief Thread function for parallel file decryption
 *
 * @param arg Thread data structure passed as void pointer
 * @return NULL (required by thread API)
 *
 * @pre arg must be a valid ThreadData pointer
 * @post File will be decrypted using the decrypt_file function
 */
void *decrypt_thread_func(void *arg) {
    ThreadData *data = (ThreadData *) arg;
    decrypt_file(data);
    return NULL;
}

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
int decrypt_single_file(const char *input_filename, const char *output_filename) {
    ThreadData data;
    data.input_filename = (char *)input_filename;
    data.output_filename = (char *)output_filename;

    decrypt_file(&data);
    return 0;
}

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
void process_decryption() {
    char **files;
    int num_files;
    list_files_for_decryption(&files, &num_files);

    if (num_files == 0) {
        printf("No files available for decryption.\n");
        return;
    }

    printf("Files available for decryption:\n");
    for (int i = 0; i < num_files; i++) {
        printf("%d: %s\n", i + 1, files[i]);
    }

    char input[256];
    int selected_files[256];
    int count = 0;

    // Get user file selection with input validation
    while (1) {
        printf("Enter file numbers to decrypt (separated by spaces): ");
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
            printf("Invalid input. Please enter valid numbers separated by spaces.\n");
        }
    }

    // Allocate memory for thread data and threads
    ThreadData *data = malloc(count * sizeof(ThreadData));
    mthread_thread_t *threads = malloc(count * sizeof(mthread_thread_t));

    // Create and launch decryption threads
    for (int i = 0; i < count; i++) {
        int index = selected_files[i];
        data[i].input_filename = files[index];

        // Generate output filename for decrypted file
        char *encrypted_ext = strstr(files[index], ".encrypted");
        if (encrypted_ext) {
            // Calculate length of original filename (without .encrypted)
            int orig_len = encrypted_ext - files[index];

            // Allocate enough space for original name + "(Decrypted)" + null terminator
            data[i].output_filename = malloc(orig_len + 12); // 11 for "(Decrypted)" + 1 for null

            // Copy original filename part
            strncpy(data[i].output_filename, files[index], orig_len);
            data[i].output_filename[orig_len] = '\0';

            // Find extension in original filename
            char *last_dot = strrchr(data[i].output_filename, '.');
            if (last_dot) {
                // Has extension, insert "(Decrypted)" before extension
                char temp[256];
                strcpy(temp, last_dot); // Save extension
                strcpy(last_dot, "(Decrypted)");
                strcat(data[i].output_filename, temp); // Add extension back
            } else {
                // No extension, add "(Decrypted)" at the end
                strcat(data[i].output_filename, "(Decrypted)");
            }
        } else {
            // This should not happen with our naming convention
            data[i].output_filename = malloc(strlen(files[index]) + 12);
            sprintf(data[i].output_filename, "%s(Decrypted)", files[index]);
        }

        // Key and IV will be retrieved in decrypt_file function
        if (mthread_create(&threads[i], NULL, decrypt_thread_func, &data[i]) != 0) {
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
    printf("  ./decrypt                           - Interactive mode\n");
    printf("  ./decrypt input.encrypted output.txt - Command line mode\n");
    printf("  ./decrypt --help                    - Display this help information\n");
}

/* ===== Main Function ===== */
/**
 * @brief Program entry point
 *
 * Handles command-line arguments, password verification, and
 * launches either interactive or command-line decryption mode.
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on success, 1 on error
 */
int main(int argc, char *argv[]) {
    // Check for command line arguments
    if (argc > 1) {
        // Help information
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage();
            return 0;
        }

        // Command line mode: decrypt input output
        if (argc == 3) {
            // Still need password verification
            FILE *admin_key_file = fopen(ADMIN_KEY_FILE, "rb");
            if (!admin_key_file) {
                printf("First use, please set administrator password: ");
                char password[256];
                scanf("%255s", password);
                set_password(password);
                printf("Password set successfully.\n");
            } else {
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

            // Execute single file decryption
            return decrypt_single_file(argv[1], argv[2]);
        } else if (argc != 1) {
            // Incorrect argument count
            printf("Invalid number of arguments.\n");
            print_usage();
            return 1;
        }
    }

    // Interactive mode
    // Check admin key file
    FILE *admin_key_file = fopen(ADMIN_KEY_FILE, "rb");
    if (admin_key_file) {
        // Check if file is empty
        fseek(admin_key_file, 0, SEEK_END);
        long file_size = ftell(admin_key_file);
        fclose(admin_key_file);

        if (file_size == 0) {
            // File is empty, prompt user to set new password
            char password[256];
            printf("Set new administrator password: ");
            scanf("%255s", password);
            set_password(password);
            printf("Password set successfully.\n");
        } else {
            // File exists and is not empty, prompt user for password
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
        // Admin key file does not exist, prompt user to set new password
        char password[256];
        printf("Set new administrator password: ");
        scanf("%255s", password);
        set_password(password);
        printf("Password set successfully.\n");
    }

    // Clear input buffer
    while (getchar() != '\n');

    printf("=== File Decryption Program ===\n");
    process_decryption();

    return 0;
}