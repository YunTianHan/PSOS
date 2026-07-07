#include <stdio.h>
#include <string.h>
#include "openssl/evp.h"

int main() {
    printf("Hello, OpenSSL!\n");

    /* 加载所有算法 */
    OpenSSL_add_all_algorithms();

    /* SM3摘要算法 */
    unsigned char md_value[EVP_MAX_MD_SIZE];        //保存输出的摘要值的数组
    unsigned int md_len;
    EVP_MD_CTX *pmdctx = EVP_MD_CTX_new();          //EVP消息结构体
    char msg1[] = "Test Message1";                  //待计算摘要的消息1
    char msg2[] = "Test Message2";                  //待计算只要的消息2
    int i=0;


    EVP_MD_CTX_init(pmdctx);                        //初始化摘要结构体

    //设置摘要算法和密码算法引擎，这里密码算法使用SM3
    //算法引擎使用OpenSSL默认引擎，即软算法
    EVP_DigestInit_ex(pmdctx,EVP_sm3(),NULL);
    EVP_DigestUpdate(pmdctx,msg1,strlen(msg1));     //调用摘要Update计算msg1的摘要
    EVP_DigestUpdate(pmdctx,msg2,strlen(msg2));     //调用摘要Update计算msg2的摘要
    EVP_DigestFinal_ex(pmdctx,md_value,&md_len);    //摘要结束，输出摘要值


    /* 打印结果 */
    printf("原始数据%s和%s的摘要为：\n",msg1,msg2);
    for(i=0;i<md_len;i++)
    {
        printf("%02X ",md_value[i]);
    }
    printf("\n");

    return 0;
}