#include "stdio.h"
#include "encrypt.h"

int algo_type;
int action_type;

const char* extract_filename(const char* path) {
    const char* filename = strrchr(path, '/');
    return (filename != NULL) ? filename + 1 : path;
}

int perform_encryption() {
    int algo_choice;
    char input_file[100];
    char output_file[100];

    printf("Select action type:\n1. Encrypting \n2. Decrypting \n3. another action\nYour choice: ");
    scanf("%d", &action_type);
    printf("Action selected: %d\n", action_type);

    printf("plz enter input file path: ");
    scanf("%s", input_file);
    printf("Input file path: %s\n", input_file);

    printf("plz enter output file path: ");
    scanf("%s", output_file);
    printf("Output file path: %s\n", output_file);

    printf("Select encryption algorithm:\n1. Symmetric encryption\n2. Asymmetric encryption\n3. Hash \n4. Hybrid encryption\nYour choice: ");
    scanf("%d", &algo_choice);
    printf("Algorithm selected: %d\n", algo_choice);

    select_encryption_algorithm(algo_choice);

    if (action_type == 1) {
        printf("Encrypting the file...\n");

        if (algo_choice == 1) {
            if (algo_type == 1) {
                unsigned char key[32];
                if (RAND_bytes(key, 32) != 1) {
                    printf("Error: Unable to generate random key\n");
                    return -1;
                }

                char key_str[65];
                for (int i = 0; i < 32; i++) {
                    sprintf(key_str + (i * 2), "%02x", key[i]);
                }
                key_str[64] = '\0';

                FILE *key_file;
                char key_filename[104];
                strcpy(key_filename, extract_filename(output_file));
                strcat(key_filename, ".key");

                key_file = fopen(key_filename, "w");
                if (key_file == NULL) {
                    printf("Error: Unable to open key file\n");
                    return -1;
                }
                if (fputs(key_str, key_file) == EOF) {
                    printf("Error: Unable to write key to file\n");
                    fclose(key_file);
                    return -1;
                }
                fclose(key_file);
                printf("Key file created: %s\n", key_filename);

                printf("Generated encryption key: %s\n", key_str);
                int encrypt_result = aes_encrypt_file(input_file, output_file, key_str);
                printf("Encryption completed. Output file: %s\n", output_file);
                return encrypt_result;
            }
            // Additional symmetric algorithms can be added here
        } else if (algo_choice == 2) {
            // Asymmetric encryption handling
        } else if (algo_choice == 3) {
            // Hash function handling
        } else if (algo_choice == 4) {
            // Hybrid encryption handling
        }
    } else if (action_type == 2) {
        printf("Decrypting the file...\n");

        if (algo_choice == 1) {
            if (algo_type == 1) {
                printf("Enter decryption key: ");
                char key_str[65];
                scanf("%64s", key_str);
                aes_decrypt_file(input_file, output_file, key_str);
                printf("Decryption completed. Output file: %s\n", output_file);
            }
            // Additional symmetric algorithms can be added here
        } else if (algo_choice == 2) {
            // Asymmetric decryption handling
        } else if (algo_choice == 3) {
            // Hash decryption handling
        } else if (algo_choice == 4) {
            // Hybrid decryption handling
        }
    } else if (action_type == 3) {
        printf("Other operation selected\n");
        exit(1);
    } else {
        printf("Error: Invalid input\n");
        exit(1);
    }
    return 0;
}

int select_encryption_algorithm(int type) {
    switch (type) {
        case 1:
            printf("Select symmetric encryption algorithm:\n1. AES\n2. Blowfish\n3. DES\nYour choice: ");
            scanf("%d", &algo_type);
            break;
        case 2:
            printf("Select asymmetric encryption algorithm:\n1. RSA\n2. DSA\nYour choice: ");
            scanf("%d", &algo_type);
            break;
        case 3:
            printf("Select hash function:\n1. MD5\n2. SHA-256\n3. SHA-3\nYour choice: ");
            scanf("%d", &algo_type);
            break;
        case 4:
            printf("Hybrid encryption is not supported. Please choose another method.\n");
            exit(1);
        default:
            printf("Error: Invalid encryption method. Please choose again.\n");
            exit(1);
    }
    return confirm_algorithm_choice(type);
}

int confirm_algorithm_choice(int type) {
    switch (type) {
        case 1:
            switch (algo_type) {
                case 1:
                    printf("AES selected.\n");
                    break;
                case 2:
                    printf("Blowfish selected.\n");
                    break;
                case 3:
                    printf("DES selected.\n");
                    break;
                default:
                    printf("Error: Invalid symmetric encryption algorithm. Please choose again.\n");
                    exit(1);
            }
            break;
        case 2:
            switch (algo_type) {
                case 1:
                    printf("RSA selected.\n");
                    break;
                case 2:
                    printf("DSA selected.\n");
                    break;
                default:
                    printf("Error: Invalid asymmetric encryption algorithm. Please choose again.\n");
                    exit(1);
            }
            break;
        case 3:
            switch (algo_type) {
                case 1:
                    printf("MD5 selected.\n");
                    break;
                case 2:
                    printf("SHA-256 selected.\n");
                    break;
                case 3:
                    printf("SHA-3 selected.\n");
                    break;
                default:
                    printf("Error: Invalid hash function. Please choose again.\n");
                    exit(1);
            }
            break;
        default:
            printf("Error: Invalid encryption method. Please choose again.\n");
            exit(1);
    }
    return 1;
}

int main(void) {
    int ret = perform_encryption();
    return ret;
}

