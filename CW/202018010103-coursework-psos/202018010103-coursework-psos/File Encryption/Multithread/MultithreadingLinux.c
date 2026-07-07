#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#define BUFFER_SIZE 10

//# LINUX
int buffer[BUFFER_SIZE];
int count = 0;
int finished = 0; // Flag indicating whether the program has finished or not
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t full = PTHREAD_COND_INITIALIZER;
pthread_cond_t empty = PTHREAD_COND_INITIALIZER;


// Producer
void *producer(void *arg) {
    int item = 1; // Item number produced by the producer
    while (item <= 1000) { // Producer produces 1000 items
        pthread_mutex_lock(&mutex); // Lock to ensure atomic operation
        // When the buffer is full, the producer needs to wait for the consumer to consume some items
        if (count == BUFFER_SIZE) {
            pthread_cond_wait(&empty, &mutex); // Unlock mutex and wait for signal of the empty condition variable
        }

        // Produce item
        buffer[count] = item; // Put item into the buffer
        printf("Producer produces item %d\n", item); // Output production log
        count++; // Increase the count of items in the buffer
        pthread_cond_signal(&full); // Send signal of the full condition variable to notify the consumer that there is a new item to consume
        pthread_mutex_unlock(&mutex); // Unlock mutex to release the lock resource
        item++; // Prepare to produce the next item
    }
// After the producer has produced 1000 items, it tells the consumer to end the program
    pthread_mutex_lock(&mutex);
    finished = 1;
    pthread_cond_signal(&empty); // Send signal of the empty condition variable to notify the consumer to end the program
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void *consumer(void *arg) {
    int item; // Item number consumed by the consumer
    while (1) { // The consumer consumes items continuously
        pthread_mutex_lock(&mutex); // Lock to ensure atomic operation
        // When the buffer is empty, the consumer needs to wait for the producer to produce some items
        if (count == 0) {
            pthread_cond_wait(&full, &mutex); // Unlock mutex and wait for signal of the full condition variable
        }

        // Consume item
        item = buffer[count - 1]; // Take an item out of the buffer
        printf("Consumer consumes item %d\n", item); // Output consumption log
        count--; // Decrease the count of items in the buffer

        // If the consumer has consumed the termination value, send the exit signal
        if (item == 1000) {
            pthread_cond_signal(&empty); // Send signal of the empty condition variable to notify the producer to exit
            pthread_mutex_unlock(&mutex); // Unlock mutex to release the lock resource
            break; // End the consumer thread
        }

        pthread_cond_signal(&empty); // Send signal of the empty condition variable to notify the producer that there is a free space to produce
        pthread_mutex_unlock(&mutex); // Unlock mutex to release the lock resource
    }
}

int main() {
//    system("chcp 65001");
    pthread_t tid1, tid2;
    pthread_create(&tid1, NULL, producer, NULL);
    pthread_create(&tid2, NULL, consumer, NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    return 0;
}
