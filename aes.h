#ifndef __AES_H__
#define __AES_H__

#define KEY_LEN_MAX     256
#define BUFF_LEN_MAX    1024
#define CIPHER_LEN_MAX  (BUFF_LEN_MAX + EVP_MAX_BLOCK_LENGTH)

int generate_key(const unsigned char *data, int data_len,
                 unsigned char *key, int key_len);

int encrypt(const unsigned char *data, int data_len,
            const unsigned char *key, int key_len,
            unsigned char *cipher, int *cipher_len);

int decrypt(const unsigned char *cipher, int cipher_len,
            const unsigned char *key, int key_len,
            unsigned char *data, int *data_len);

int test_correctness(const unsigned char *data, int data_len,
                     const unsigned char *encr_data, int encr_data_len,
                     const unsigned char *key, int key_len);

#endif /* __AES_H__ */
