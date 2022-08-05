#ifndef __IO_H__
#define __IO_H__

int input(unsigned char *login, int *login_len,
          unsigned char *password, int *password_len,
          int *key_len);

int output(const char *type,
           const unsigned char *data, int data_len,
           const unsigned char *cipher, int cipher_len,
           const unsigned char *key, int key_len);

#endif /* __IO_H__ */
