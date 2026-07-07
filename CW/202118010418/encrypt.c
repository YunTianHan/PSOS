//
// Created by Yun on 25-5-12.
//

#include "common.h"

void *encrypt_file_thread(void *arg) {
    ThreadData *d = (ThreadData *)arg;
    FILE *fin = fopen(d->input_filename, "rb");
    FILE *fout = fopen(d->output_filename, "wb");
    if (!fin || !fout) HANDLE_ERRORS(__FILE__, __LINE__, "Open file error");

    AES_KEY aes_key;
    // 随机 IV
    if (!RAND_bytes(d->iv, IV_LENGTH)) HANDLE_ERRORS(__FILE__, __LINE__, "RAND_bytes failed");
    fwrite(d->iv, 1, IV_LENGTH, fout);

    if (AES_set_encrypt_key(d->key, 256, &aes_key) < 0)
        HANDLE_ERRORS(__FILE__, __LINE__, "AES_set_encrypt_key failed");

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int len;
    while ((len = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        int pad = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
        memset(inbuf + len, pad, pad);
        AES_cbc_encrypt(inbuf, outbuf, len + pad, &aes_key, d->iv, AES_ENCRYPT);
        fwrite(outbuf, 1, len + pad, fout);
        memset(inbuf, 0, BUFFER_SIZE);
        memset(outbuf, 0, BUFFER_SIZE + AES_BLOCK_SIZE);
    }

    fclose(fin);
    fclose(fout);

    // 生成并保存加密文件哈希
    unsigned char hash[HASH_LENGTH];
    sha256_file(d->output_filename, hash);
    save_hash_to_file(hash, HASH_VALUE_FILE);

    printf("[Encrypt] %s -> %s\n", d->input_filename, d->output_filename);
    return NULL;
}

void encrypt_process(char **files, int count) {
    ThreadData *td = malloc(count * sizeof(ThreadData));
    mthread_thread_t *ths = malloc(count * sizeof(mthread_thread_t));

    for (int i = 0; i < count; i++) {
        td[i].input_filename  = files[i];
        td[i].output_filename = malloc(strlen(files[i]) + 11);
        snprintf((char*)td[i].output_filename, strlen(files[i]) + 11,
                 "%s.encrypted", files[i]);
        memcpy(td[i].key, "01234567890123456789012345678901", KEY_LENGTH);

        if (mthread_create(&ths[i], NULL, encrypt_file_thread, &td[i]) != 0)
            HANDLE_ERRORS(__FILE__, __LINE__, "mthread_create failed");
    }
    for (int i = 0; i < count; i++) {
        mthread_join(ths[i], NULL);
        free((char*)td[i].output_filename);
    }
    free(td);
    free(ths);
}

