#include <minix/mthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "decrypt.h"

int main(int argc, char *argv[]) {
    // Initialize variables
    int j = 0;
    // Check if there are enough arguments
    if (argc < 4 || (argc - 2) % 2 != 0) {
        fprintf(stderr, "Usage: %s <key> <file1> <output1> [<file2> <output2> ...]\n", argv[0]);
        return 1;
    }
    // Create threads
    while (j < (argc - 2) / 2) {
        // Convey data
        struct args args;
        args.key = argv[1];
        args.input = argv[j * 2 + 2];
        args.output = argv[j * 2 + 3];
        mthread_thread_t thread;
        mthread_create(&thread, NULL, decrypt, (void *)&args); // Create thread
        mthread_join(thread, NULL); // Add to thread list
        j += 1;
    }
    return 0;
}