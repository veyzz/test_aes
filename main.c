#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "defines.h"
#include "io.h"
#include "aes.h"

int main(int arc, char *argv[])
{
  int ret = 0;
  unsigned char key[KEY_LEN_MAX];
  unsigned char login[BUFF_LEN_MAX];
  unsigned char password[BUFF_LEN_MAX];
  unsigned char cipher1[CIPHER_LEN_MAX];
  unsigned char cipher2[CIPHER_LEN_MAX];
  unsigned char decrypted1[BUFF_LEN_MAX];
  unsigned char decrypted2[BUFF_LEN_MAX];
  int key_len;
  int login_len;
  int password_len;
  int cipher1_len;
  int cipher2_len;
  int decrypted1_len;
  int decrypted2_len;

  ret = input(login, &login_len, password, &password_len, &key_len);
  if (ret < 0)
  {
    printf("Wrong input\n");
    return -1;
  }

  ret = generate_key(login, login_len, key, key_len);
  if (ret < 0)
  {
    printf("Could not generate key\n");
    return -1;
  }

  ret = encrypt(login, login_len,
                key, key_len,
                cipher1, &cipher1_len);
  if (ret < 0)
  {
    printf("Could not encrypt login\n");
    return -1;
  }

  ret = encrypt(password, password_len,
                key, key_len,
                cipher2, &cipher2_len);
  if (ret < 0)
  {
    printf("Could not encrypt password\n");
    return -1;
  }

  output("Login", login, login_len, cipher1, cipher1_len, key, key_len);
  output("Password", password, password_len, cipher2, cipher2_len, key, key_len);

  ret = test_correctness(login, login_len,
                         cipher1, cipher1_len,
                         key, key_len);
  if (ret < 0)
  {
    printf("Incorrect encryption/decryption\n");
    return -1;
  }

  ret = test_correctness(password, password_len,
                         cipher2, cipher2_len,
                         key, key_len);
  if (ret < 0)
  {
    printf("Incorrect encryption/decryption\n");
    return -1;
  }

  return 0;
}
