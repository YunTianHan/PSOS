cmake_minimum_required(VERSION 3.27)
project(202018010210_PSOS_code C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(202018010210_PSOS_code
        decrypt.c
        decrypt.h
        encrypt.c
        encrypt.h)

include_directories("D:\\OpenSSL-Win64\\include")
link_directories("D:\\OpenSSL-Win64\\lib")
target_link_libraries(202018010210_PSOS_code crypto ssl)
