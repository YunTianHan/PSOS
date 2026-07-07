cmake_minimum_required(VERSION 3.28)
project(201918010102_PSOS_FECode)

set(CMAKE_CXX_STANDARD 17)

set(INC_DIR D:\\OpenSSL-Win64\\include)
set(LINK_DIR D:\\OpenSSL-Win64\\lib)

include_directories(${INC_DIR})
link_directories(${LINK_DIR})
link_libraries(openssl libcrypto)

add_executable(201918010102_PSOS_FECode
        encrypt.c
        decrypt.c
        encrypt.h
        decrypt.h
)

target_link_libraries(201918010102_PSOS_FECode openssl)
