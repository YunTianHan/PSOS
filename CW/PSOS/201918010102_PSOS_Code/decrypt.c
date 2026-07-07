#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <minix/mthread.h>
#include "decrypt.h"

int main(int argc, char *argv[]) {
    mthread_thread_t thread[argc - 1];
    int j =0;
    for (int i = 2; i<argc; i++){
        struct args args;
        args.key = (unsigned char *)argv[1];
        args.input = (unsigned char *)argv[i];
        args.output = (unsigned char *)argv[i+1];
        i++;
        mthread_create(&thread[j], NULL, (void *) &args, decrypt);
        mthread_join(thread[j], NULL);
        j++;
    }
    return 0;
}
