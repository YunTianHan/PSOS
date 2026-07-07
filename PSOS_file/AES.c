#include <minix/mthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 128
#define AES_BLOCK_SIZE 16

void handleFileError(const char *message, FILE *file) {
    fprintf(stderr, "%s\n", message);
    if (file != NULL) {
        fclose(file);
    }
}

unsigned long getFileSize(const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        handleFileError("Unable to open file", file);
        return 0;
    }

    fseek(file, 0, SEEK_END);
    unsigned long fileSize = ftell(file);
    fclose(file);

    return fileSize;
}

void encryptFile(const char *filepath, const unsigned char *key) {
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        handleFileError("Unable to open file", file);
        return;
    }

    char encryptedFilename[256];
    snprintf(encryptedFilename, sizeof(encryptedFilename), "%s.enc", filepath);
    FILE *encryptedFile = fopen(encryptedFilename, "wb");
    if (encryptedFile == NULL) {
        handleFileError("Unable to create encrypted file", file);
        return;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    AES_KEY aesKey;
    AES_set_encrypt_key(key, AES_KEY_SIZE, &aesKey);

    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];

    // Calculate the number of padding bytes
    unsigned long fileSize = getFileSize(filepath);
    int padding = AES_BLOCK_SIZE - (fileSize % AES_BLOCK_SIZE);

    // Write IV and padding byte count
    fwrite(iv, sizeof(unsigned char), AES_BLOCK_SIZE, encryptedFile);
    fwrite(&padding, sizeof(unsigned char), 1, encryptedFile);

    memset(indata, 0x00, sizeof(indata));
    memset(outdata, 0x00, sizeof(outdata));
    int bytesRead;
    while ((bytesRead = fread(indata, sizeof(unsigned char), AES_BLOCK_SIZE, file)) > 0) {
        AES_cbc_encrypt(indata, outdata, AES_BLOCK_SIZE, &aesKey, iv, AES_ENCRYPT);
        fwrite(outdata, sizeof(unsigned char), AES_BLOCK_SIZE, encryptedFile);
        memset(indata, 0x00, sizeof(indata));
        memset(outdata, 0x00, sizeof(outdata));
    }

    fclose(file);
    fclose(encryptedFile);

    printf("File %s encrypted\n", filepath);
    printf("Encrypted file: %s\n", encryptedFilename);
}

void decryptFile(const char *encryptedFilepath, const unsigned char *key) {
    FILE *encryptedFile = fopen(encryptedFilepath, "rb");
    if (encryptedFile == NULL) {
        handleFileError("Unable to open encrypted file", encryptedFile);
        return;
    }

    char decryptedFilename[256];
    snprintf(decryptedFilename, sizeof(decryptedFilename), "%s.dec", encryptedFilepath);
    FILE *decryptedFile = fopen(decryptedFilename, "wb");
    if (decryptedFile == NULL) {
        handleFileError("Unable to create decrypted file", decryptedFile);
        return;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    fread(iv, sizeof(unsigned char), AES_BLOCK_SIZE, encryptedFile);

    AES_KEY aesKey;
    AES_set_decrypt_key(key, AES_KEY_SIZE, &aesKey);

    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];

    // Read padding byte count
    int padding;
    fread(&padding, sizeof(unsigned char), 1, encryptedFile);

    memset(indata, 0x00, sizeof(indata));
    memset(outdata, 0x00, sizeof(outdata));
    int bytesRead;
    while ((bytesRead = fread(indata, sizeof(unsigned char), AES_BLOCK_SIZE, encryptedFile)) > 0) {
        AES_cbc_encrypt(indata, outdata, AES_BLOCK_SIZE, &aesKey, iv, AES_DECRYPT);
        // Check if it's the last block and remove padding bytes
        if (feof(encryptedFile)) {
            fwrite(outdata, sizeof(unsigned char), AES_BLOCK_SIZE - padding, decryptedFile);
        } else {
            fwrite(outdata, sizeof(unsigned char), AES_BLOCK_SIZE, decryptedFile);
        }
        memset(indata, 0x00, sizeof(indata));
        memset(outdata, 0x00, sizeof(outdata));
    }

    fclose(encryptedFile);
    fclose(decryptedFile);

    printf("File %s decrypted\n", encryptedFilepath);
    printf("Decrypted file: %s\n", decryptedFilename);
}

void processFiles(const char *directory, const unsigned char *key, int *selectedFiles, int fileCount, int operationChoice) {
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(directory)) != NULL) {
        int index = 1;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG) { // Process regular files only
                char filepath[256];
                snprintf(filepath, sizeof(filepath), "%s/%s", directory, ent->d_name);

                for (int i = 0; i < fileCount; i++) {
                    if (selectedFiles[i] == index) {
                        if (operationChoice == 1) {
                            encryptFile(filepath, key);
                        } else if (operationChoice == 2) {
                            decryptFile(filepath, key);
                        }
                        break;
                    }
                }
                index++;
            }
        }
        closedir(dir);
    } else {
        handleFileError("Unable to open directory", NULL);
    }
}

int main() {
    const unsigned char key[AES_KEY_SIZE / 8] = "abcd0123";
    char directory[256] = "/mnt/PSOS"; // 修改文件夹路径为/mnt/PSOS
    int operationChoice;

    DIR *dir = opendir(directory);
    if (dir == NULL) {
        fprintf(stderr, "Unable to open directory: %s\n", directory);
        return 0;
    }

    struct dirent *entry;
    int fileCount = 0;

    printf("File list:\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            printf("%d. %s\n", ++fileCount, entry->d_name);
        }
    }

    closedir(dir);

    if (fileCount == 0) {
        printf("Directory is empty\n");
        return 0;
    }

    int *selectedFiles = (int *)malloc(fileCount * sizeof(int));
    int selectedFileCount = 0;

    printf("Enter the file numbers to process (separated by spaces, 0 to quit): ");
    char fileNumbers[256];
    fgets(fileNumbers, sizeof(fileNumbers), stdin);

    char *token = strtok(fileNumbers, " ");
    while (token != NULL) {
        int fileNumber = atoi(token);
        if (fileNumber < 0 || fileNumber > fileCount) {
            printf("Invalid file number: %d\n", fileNumber);
        } else if (fileNumber == 0) {
            break;
        } else {
            selectedFiles[selectedFileCount++] = fileNumber;
        }
        token = strtok(NULL, " ");
    }

    printf("Enter operation choice (1 - Encrypt, 2 - Decrypt): ");
    scanf("%d", &operationChoice);
    getchar(); // Read the trailing newline

    processFiles(directory, key, selectedFiles, selectedFileCount, operationChoice);

    free(selectedFiles);

    return 0;
}
