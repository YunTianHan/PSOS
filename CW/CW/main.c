#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>

#define KEY_SIZE 32             // AES-256 需要 32 字节密钥
#define IV_SIZE 16              // AES CBC 模式需要 16 字节初始化向量
#define DATA_CHUNK 1024         // 分块处理，每个线程处理 1024 字节

// 线程传递的数据结构
typedef struct {
    FILE *input_fp;
    FILE *output_fp;
    unsigned char *encryption_key; // 指向密钥的指针
    unsigned char *init_vector;    // 指向 IV 的指针
    long data_start_pos;           // 当前数据块在文件中的起始位置
    size_t data_chunk_len;         // 当前数据块的长度
    bool encrypt_mode;             // true：加密；false：解密
} ThreadData;

// 错误处理函数：打印错误并退出
void error_handler(const char *errorMsg) {
    fprintf(stderr, "%s\n", errorMsg);
    exit(EXIT_FAILURE);
}

// 线程处理函数：对指定块进行加密或解密处理
void* handle_data_chunk(void* thread_data_ptr) {
    ThreadData* thread_data = (ThreadData*) thread_data_ptr;

    // 数据缓冲区
    unsigned char data_buffer[DATA_CHUNK];
    // 输出缓冲区大小需要额外留出 EVP_MAX_BLOCK_LENGTH 字节空间
    unsigned char processed_buffer[DATA_CHUNK + EVP_MAX_BLOCK_LENGTH];
    int out_len = 0, final_out_len = 0;

    // 创建新的上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        error_handler("Failed to allocate cipher context.");
    }

    // 根据模式初始化上下文
    if (thread_data->encrypt_mode) {
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                thread_data->encryption_key, thread_data->init_vector)) {
            error_handler("Encryption initialization failed.");
        }
    } else {
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                thread_data->encryption_key, thread_data->init_vector)) {
            error_handler("Decryption initialization failed.");
        }
    }

    // 定位到当前线程负责的数据块起始位置
    if (fseek(thread_data->input_fp, thread_data->data_start_pos, SEEK_SET) != 0) {
        error_handler("Failed to set input file position.");
    }
    if (fseek(thread_data->output_fp, thread_data->data_start_pos, SEEK_SET) != 0) {
        error_handler("Failed to set output file position.");
    }

    // 从文件中读取数据块
    size_t read_len = fread(data_buffer, 1, thread_data->data_chunk_len, thread_data->input_fp);
    if (read_len == 0 && ferror(thread_data->input_fp)) {
        error_handler("Error reading input file.");
    }

    // 执行数据加密或解密处理
    if (thread_data->encrypt_mode) {
        if (!EVP_EncryptUpdate(ctx, processed_buffer, &out_len, data_buffer, read_len)) {
            error_handler("Encryption update failed.");
        }
        if (!EVP_EncryptFinal_ex(ctx, processed_buffer + out_len, &final_out_len)) {
            error_handler("Encryption finalization failed.");
        }
    } else {
        if (!EVP_DecryptUpdate(ctx, processed_buffer, &out_len, data_buffer, read_len)) {
            error_handler("Decryption update failed.");
        }
        if (!EVP_DecryptFinal_ex(ctx, processed_buffer + out_len, &final_out_len)) {
            error_handler("Decryption finalization failed.");
        }
    }

    int total_out = out_len + final_out_len;
    if (fwrite(processed_buffer, 1, total_out, thread_data->output_fp) != (size_t)total_out) {
        error_handler("Error writing to output file.");
    }

    EVP_CIPHER_CTX_free(ctx);
    pthread_exit(NULL);
}

// 主过程函数，负责文件加解密整体流程
void perform_crypt(const char* input_path, const char* output_path,
                   const char* key_path, const char* iv_path, bool mode) {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    FILE *input_file = fopen(input_path, "rb");
    FILE *output_file = fopen(output_path, "wb+");
    FILE *key_file, *iv_file;

    // 根据模式选择不同的文件打开方式
    if (mode) { // 加密时：新生成密钥及 IV，写入文件
        key_file = fopen(key_path, "wb");
        iv_file = fopen(iv_path, "wb");
    } else {    // 解密时：从文件中读取密钥和 IV
        key_file = fopen(key_path, "rb");
        iv_file = fopen(iv_path, "rb");
    }

    if (!input_file || !output_file || !key_file || !iv_file) {
        error_handler("Could not open one or more files.");
    }

    if (mode) {
        if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
            error_handler("Failed to generate encryption key or IV.");
        }
        if (fwrite(key, sizeof(key), 1, key_file) != 1 ||
            fwrite(iv, sizeof(iv), 1, iv_file) != 1) {
            error_handler("Failed to write key or IV to file.");
        }
    } else {
        if (fread(key, sizeof(key), 1, key_file) != 1 ||
            fread(iv, sizeof(iv), 1, iv_file) != 1) {
            error_handler("Failed to read key or IV from file.");
        }
    }

    // 获取输入文件大小
    if (fseek(input_file, 0, SEEK_END) != 0) {
        error_handler("Failed to seek input file.");
    }
    long file_size = ftell(input_file);
    if (file_size < 0) {
        error_handler("Failed to determine file size.");
    }
    fseek(input_file, 0, SEEK_SET);

    // 根据数据块大小计算线程数量
    int thread_count = (file_size + DATA_CHUNK - 1) / DATA_CHUNK;
    pthread_t thread_ids[thread_count];
    ThreadData thread_data_array[thread_count];

    // 为每个线程准备任务数据，并创建线程
    for (int i = 0; i < thread_count; i++) {
        thread_data_array[i].input_fp = input_file;
        thread_data_array[i].output_fp = output_file;
        thread_data_array[i].data_start_pos = i * DATA_CHUNK;
        thread_data_array[i].data_chunk_len = (i == thread_count - 1)
            ? (file_size - i * DATA_CHUNK) : DATA_CHUNK;
        thread_data_array[i].encrypt_mode = mode;
        thread_data_array[i].encryption_key = key;
        thread_data_array[i].init_vector = iv;

        if (pthread_create(&thread_ids[i], NULL, handle_data_chunk, &thread_data_array[i]) != 0) {
            error_handler("Failed to create thread.");
        }
    }

    // 等待所有线程结束
    for (int i = 0; i < thread_count; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    fclose(input_file);
    fclose(output_file);
    fclose(key_file);
    fclose(iv_file);
}

// 主函数，负责用户交互和模式选择
int main() {
    char operation[10];
    char input_filename[256], output_filename[256], key_filename[256], iv_filename[256];

    printf("Choose 'encrypt' or 'decrypt': ");
    scanf("%9s", operation);

    printf("Enter the input file name: ");
    scanf("%255s", input_filename);
    printf("Enter the output file name: ");
    scanf("%255s", output_filename);
    printf("Enter the key file name: ");
    scanf("%255s", key_filename);
    printf("Enter the IV file name: ");
    scanf("%255s", iv_filename);

    bool is_encrypt = (strcmp(operation, "encrypt") == 0);
    if (is_encrypt) {
        perform_crypt(input_filename, output_filename, key_filename, iv_filename, true);
        printf("Encryption process completed successfully.\n");
    } else if (strcmp(operation, "decrypt") == 0) {
        perform_crypt(input_filename, output_filename, key_filename, iv_filename, false);
        printf("Decryption process completed successfully.\n");
    } else {
        error_handler("Invalid operation specified.");
    }
    return 0;
}

