# 国密SM2签名
 + 调用方法：
 + 引用sm2.h
###
    /*
    content 欲签名内容
    contentlen 内容长度
    prikey 私钥，HEX格式
    out 输出缓冲区，至少64字节，输出长度为固定64字节
    */
    void my_sm2_sign(const char* content, int contentlen, const char* prikey, char* out);

## 注：
 + 所有代码是从openssl1.1.1里面抠出来的
 + 没有验签，可以从openssl1.1.1源码里面抠
 + 兼容openssl1.0.2/1.1.0/1.1.1
