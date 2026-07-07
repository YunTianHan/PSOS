//
// Created by Yun on 25-5-12.
//

#include "common.h"

void *decrypt_file_thread(void *arg) {
    ThreadData *d = (ThreadData *)arg;
    FILE *fin = fopen(d->input_filename, "rb");
    FILE *fout = fopen(d->output_filename, "wb");
    if (!fin || !fout) HANDLE_ERRORS(__FILE__, __LINE__, "Open file error");

    AES_KEY aes_key;
    // 读取 IV
    if (fread(d->iv, 1, IV_LENGTH, fin) != IV_LENGTH)
        HANDLE_ERRORS(__FILE__, __LINE__, "Read IV failed");
    if (AES_set_decrypt_key(d->key, 256, &aes_key) < 0)
        HANDLE_ERRORS(__FILE__, __LINE__, "AES_set_decrypt_key failed");

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE];
    int len;
    while ((len = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        AES_cbc_encrypt(inbuf, outbuf, len, &aes_key, d->iv, AES_DECRYPT);
        // 如果是最后一块，去除填充
        if (feof(fin)) {
            int pad = outbuf[len - 1];
            if (pad > 0 && pad <= AES_BLOCK_SIZE) len -= pad;
        }
        fwrite(outbuf, 1, len, fout);
        memset(inbuf, 0, BUFFER_SIZE);
        memset(outbuf, 0, BUFFER_SIZE);
    }

    fclose(fin);
    fclose(fout);
    printf("[Decrypt] %s -> %s\n", d->input_filename, d->output_filename);
    return NULL;
}

void decrypt_process(char **files, int count) {
    // 先校验哈希
    char *valid[100];
    int vcnt = 0;
    for (int i = 0; i < count; i++) {
        unsigned char hash[HASH_LENGTH];
        sha256_file(files[i], hash);
        if (!hash_in_file(hash, HASH_VALUE_FILE)) {
            printf("Hash not found for %s. Continue? (y/n): ", files[i]);
            char c = getchar(); while (getchar()!='\n');
            if (c!='y' && c!='Y') continue;
        }
        valid[vcnt++] = files[i];
    }
    if (vcnt == 0) {
        printf("No files to decrypt after verification.\n");
        return;
    }

    ThreadData *td = malloc(vcnt * sizeof(ThreadData));
    mthread_thread_t *ths = malloc(vcnt * sizeof(mthread_thread_t));
    for (int i = 0; i < vcnt; i++) {
        td[i].input_filename  = valid[i];
        td[i].output_filename = malloc(strlen(valid[i]) + 11);
        snprintf((char*)td[i].output_filename, strlen(valid[i]) + 11,
                 "%s.decrypted", valid[i]);
        memcpy(td[i].key, "01234567890123456789012345678901", KEY_LENGTH);

        if (mthread_create(&ths[i], NULL, decrypt_file_thread, &td[i]) != 0)
            HANDLE_ERRORS(__FILE__, __LINE__, "mthread_create failed");
    }
    for (int i = 0; i < vcnt; i++) {
        mthread_join(ths[i], NULL);
        free((char*)td[i].output_filename);
    }
    free(td);
    free(ths);
}
