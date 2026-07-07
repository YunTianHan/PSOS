#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "encrypt.h"
//The ThreadData structure is used to encapsulate data that can be passed to a thread or used in multithreaded programming.
// It allows multiple threads to operate on different instances of the structure,
// each with its own file path, output file, key string, and result.
struct ThreadData {
    const char* file_path;
    const char* out_file;
    const char* key_string;
    int result;
};


void* aes_encrypt_thread(void* arg) {
    struct ThreadData* data = (struct ThreadData*)arg;
    FILE* in_fp = NULL;
    FILE* out_fp = NULL;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char buffer[1024];
    int bytes_read, bytes_written;
    int total_bytes_written = 0;
    EVP_CIPHER_CTX* ctx;


    if ((in_fp = fopen(data->file_path, "rb")) == NULL) {
        perror("fopen");
        data->result = -1;
        return NULL;
    }

// open the output file
    if ((out_fp = fopen(data->out_file, "wb")) == NULL) {
        perror("fopen");
        fclose(in_fp);
        data->result = -1;
        return NULL;
    }

    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                        (const unsigned char*)data->key_string, strlen(data->key_string), 1, key, iv))
    {
        fprintf(stderr, "ERROR: Failed to generate AES key and IV\n");
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }




    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: Failed to create cipher context\n");
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "ERROR: Failed to initialize cipher context\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in_fp)) > 0) {
        if (EVP_EncryptUpdate(ctx, buffer, &bytes_written, buffer, bytes_read) != 1) {
            fprintf(stderr, "Error: Failed to encrypt data\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_fp);
            fclose(out_fp);
            data->result = -1;
            return NULL;
        }
        total_bytes_written += bytes_written;
        fwrite(buffer, 1, bytes_written, out_fp);
    }

    if (EVP_EncryptFinal_ex(ctx, buffer, &bytes_written) != 1) {
        fprintf(stderr, "Error: Failed to complete cipher context\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }
    total_bytes_written += bytes_written;
    fwrite(buffer, 1, bytes_written, out_fp);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_fp);
    fclose(out_fp);
    printf("Do you want to delete the original file:%s(yes/no):", data->file_path);
    char delete_original_file[4];
    scanf("%s", delete_original_file);
    if (strcmp(delete_original_file, "yes") == 0) {
        int res = remove(data->file_path);
        if (res != 0) {
            fprintf(stderr, "Error: Failed to delete original file\n");
            data->result = -1;
            return NULL;
        }
    }
    data->result = total_bytes_written;
    return NULL;
}

int aes_encrypt_file(const char* file_path, const char* out_file, const char* key_string) {
    pthread_t thread;
    struct ThreadData data;
    data.file_path = file_path;
    data.out_file = out_file;
    data.key_string = key_string;
//The function aes_encrypt_file takes three arguments: file_path (input file path), out_file (output file path), and key_string (encryption key string). It initializes a pthread_t variable thread to represent the thread that will perform the encryption.
// It also declares a struct ThreadData variable data to hold the relevant information needed by the thread.
    int result = pthread_create(&thread, NULL, aes_encrypt_thread, (void*)&data);
    if (result != 0) {
        fprintf(stderr, "Error: Failed to create thread\n");
        return -1;
    }
//The pthread_create function is called to create a new thread. It takes several arguments: the thread variable to store the created thread identifier, NULL for default thread attributes, the aes_encrypt_thread function to be executed by the thread,
// and (void*)&data to pass the data structure as an argument to the thread function.
//If the thread creation fails (the pthread_create function returns a non-zero value),
// an error message is printed, and the function returns -1 to indicate an error.
    result = pthread_join(thread, NULL);
    if (result != 0) {
        fprintf(stderr, "Error: Failed to join thread\n");
        return -1;
    }

    return data.result;
}


void* aes_decrypt_thread(void* arg) {
    struct ThreadData* data = (struct ThreadData*)arg;
    FILE* in_fp = NULL;
    FILE* out_fp = NULL;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char buffer[1024];
    int bytes_read, bytes_written;
    int total_bytes_written = 0;
    EVP_CIPHER_CTX* ctx;

    if ((in_fp = fopen(data->file_path, "rb")) == NULL) {
        perror("fopen");
        data->result = -1;
        return NULL;
    }

    if ((out_fp = fopen(data->out_file, "wb")) == NULL) {
        perror("fopen");
        fclose(in_fp);
        data->result = -1;
        return NULL;
    }

    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                        (const unsigned char*)data->key_string, strlen(data->key_string), 1, key, iv)) {
        fprintf(stderr, "ERROR: Failed to generate AES key and IV\n");
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: Failed to create cipher context\n");
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "ERROR: Failed to initialize cipher context\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in_fp)) > 0) {
        if (EVP_DecryptUpdate(ctx, buffer, &bytes_written, buffer, bytes_read) != 1) {
            fprintf(stderr, "Error: Failed to decrypt data\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_fp);
            fclose(out_fp);
            data->result = -1;
            return NULL;
        }
        total_bytes_written += bytes_written;
        fwrite(buffer, 1, bytes_written, out_fp);
    }

    if (EVP_DecryptFinal_ex(ctx, buffer, &bytes_written) != 1) {
        fprintf(stderr, "Error: Failed to complete cipher context\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_fp);
        fclose(out_fp);
        data->result = -1;
        return NULL;
    }
    total_bytes_written += bytes_written;
    fwrite(buffer, 1, bytes_written, out_fp);

    // Release the decryption context and close the file
    EVP_CIPHER_CTX_free(ctx);
    fclose(in_fp);
    fclose(out_fp);

    data->result = total_bytes_written;
    return NULL;
}

int aes_decrypt_file(const char* file_path, const char* out_file, const char* key_string) {
    pthread_t thread;
    struct ThreadData data;
    data.file_path = file_path;
    data.out_file = out_file;
    data.key_string = key_string;

    int result = pthread_create(&thread, NULL, aes_decrypt_thread, (void*)&data);
    if (result != 0) {
        fprintf(stderr, "Error: Failed to create thread\n");
        return -1;
    }
    result = pthread_join(thread, NULL);
    if (result != 0) {
        fprintf(stderr, "Error: Failed to join thread\n");
        return -1;
    }

    return data.result;
}

