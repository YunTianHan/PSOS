#include <unistd.h>
#include <stdio.h>

void one() {
  for (int x=0; x<100; x++) {
    printf("One.");
  }
}

void two() {
  for (int x=0; x<100; x++) {
    printf("Two.");
  }
}


int main() {
  if (fork()) {
    two(); 
  } else {
    one();
  }
 return 0;
}