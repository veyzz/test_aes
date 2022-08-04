#ifndef __AES_H__
#define __AES_H__

#define KEY_LEN_MAX     256
#define BUFF_LEN_MAX    1024
#define CIPHER_LEN_MAX  (BUFF_LEN_MAX + EVP_MAX_BLOCK_LENGTH)

int encrypt(const char *data, int data_len,
            const char *key, int key_len,
            char *cipher, int *cipher_len);

int decrypt(const char *cipher, int cipher_len,
            const char *key, int key_len,
            char *data, int *data_len);

#endif /* __AES_H__ */
