cmake_minimum_required(VERSION 3.10)
project(CW C)

set(CMAKE_C_STANDARD 99)

# 手动设定 OpenSSL 的头文件和库目录（注意路径中的斜杠）
set(OPENSSL_INCLUDE_DIR "C:/msys64/mingw64/include")
set(OPENSSL_LIB_DIR "C:/msys64/mingw64/lib")

# 将指定的目录加入到编译器搜索中
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIB_DIR})

add_executable(CW main.c)

# 链接时使用 -lcrypto 和 -lssl（MinGW 会自动加 lib 前缀）
target_link_libraries(CW PRIVATE crypto ssl pthread)


