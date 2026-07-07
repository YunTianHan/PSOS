#include <minix/mthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "encrypt.h"

int main(int argc, char *argv[]) {
    // Initialize variables
    int j = 0;
    mthread_thread_t thread;

    // Check if there are enough arguments
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <key> <file1> [<file2> ...]\n", argv[0]);
        return 1;
    }

    // Create threads
    while (j < argc - 2) {
        // Convey data
        struct args args;
        args.key = argv[1];
        args.input = argv[j + 2];

        // Allocate memory for the thread
        mthread_thread_t *thread_ptr = (mthread_thread_t *)malloc(sizeof(mthread_thread_t));
        if (thread_ptr == NULL) {
            fprintf(stderr, "Failed to allocate memory for thread\n");
            return 1;
        }

        // Create thread
        mthread_create(thread_ptr, NULL, encrypt, (void *)&args);
        mthread_join(*thread_ptr, NULL); // Add to thread list

        // Free memory for the thread
        free(thread_ptr);

        j += 1;
    }

    return 0;
}