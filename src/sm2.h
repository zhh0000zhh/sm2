/*
 content 欲签名内容
 contentlen 内容长度
 prikey 私钥，HEX格式
 out 输出缓冲区，至少64字节，输出长度为固定64字节
 */
void my_sm2_sign(const char* content, int contentlen, const char* prikey, char* out);