cmake_minimum_required(VERSION 3.15)
project(FileEncryption)

set(CMAKE_CXX_STANDARD 11)

# Set OpenSSL paths
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIB_DIR "${OPENSSL_ROOT_DIR}/lib")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})

# Link OpenSSL libraries
add_executable(${PROJECT_NAME} main.c scanf.c encrypt.c)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
