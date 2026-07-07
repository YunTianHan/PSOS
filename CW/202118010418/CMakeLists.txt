cmake_minimum_required(VERSION 3.29)
project(202118010418 C)

set(CMAKE_C_STANDARD 99)

add_library(202118010418 STATIC
        common.h
        encrypt.c
        decrypt.c
        main.c)
