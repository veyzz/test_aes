#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "aes.h"

int main(int arc, char *argv[])
{
  int ret = 0;
  unsigned char key[KEY_LEN_MAX] = "01234567890123456789012345678901";
  unsigned char data[BUFF_LEN_MAX] = "HELLO WORLD!";
  unsigned char cipher_txt[CIPHER_LEN_MAX];
  unsigned char decrypted_txt[BUFF_LEN_MAX];
  int cipher_txt_len, decrypted_txt_len;

  ret = encrypt(data, strlen(data),
                key, strlen(key),
                cipher_txt, &cipher_txt_len);
  if (ret == -1)
  {
    return -1;
  }

  printf("CIPHER IS:\n");
  BIO_dump_fp(stdout, (const char *)cipher_txt, cipher_txt_len);
  printf("Encrypted text is:\n");
  printf("%s\n", cipher_txt);

  printf("\n----\n\n");

  ret = decrypt(cipher_txt, cipher_txt_len,
                key, strlen(key),
                decrypted_txt, &decrypted_txt_len);
  if (ret == -1)
  {
    return -1;
  }

  decrypted_txt[decrypted_txt_len] = '\0';

  printf("DATA IS:\n");
  BIO_dump_fp(stdout, (const char *)decrypted_txt, cipher_txt_len);
  printf("Decrypted text is:\n");
  printf("%s\n", decrypted_txt);

  return 0;
}
