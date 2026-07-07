cmake_minimum_required(VERSION 3.29)
project(PSOS C)

set(CMAKE_C_STANDARD 11)

add_library(PSOS STATIC
        encrypt.c
        encrypt.c)

