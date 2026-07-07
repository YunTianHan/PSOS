cmake_minimum_required(VERSION 3.17)
project(05_OpenSSL C)

set(CMAKE_C_STANDARD 99)


#定义两个变量，表示头文件路径和库路径
set(INC_DIR C:\\msys64\\mingw64\\include)
set(LINK_DIR C:\\msys64\\mingw64\\lib)

#依次设置头文件目录、库目录、要链接的库 (在add_executable 之前)
include_directories(${INC_DIR})
link_directories(${LINK_DIR})
link_libraries(libcrypto)


add_executable(05_OpenSSL main.c)

#链接库 在add_executable之后 03_OpenSSL为工程名 ssl为库名称
target_link_libraries(05_OpenSSL crypto ssl pthread )
