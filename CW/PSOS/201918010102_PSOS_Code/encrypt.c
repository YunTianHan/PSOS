#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <minix/mthread.h>
#include "encrypt.h"

int main(int argc, char *argv[]) {
    mthread_thread_t thread[argc - 1];
    int j =0;
    for (int i = 2; i < argc; i++){
        struct args args;
        args.key = (unsigned char *)argv[1];
        args.input = (unsigned char *)argv[i];
        mthread_create(&thread[j], NULL, (void *) &args, encrypt);
        mthread_join(thread[j], NULL);
        j++;
    }
    return 0;
}
