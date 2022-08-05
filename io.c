#include <stdio.h>
#include <string.h>
#include "defines.h"
#include "io.h"

int input(unsigned char *login, int *login_len,
          unsigned char *password, int *password_len,
          int *key_len)
{
  int ret = 0;
  int len;

  printf("> Enter login: ");
  fgets(login, BUFF_LEN_MAX, stdin);

  len = strlen(login);
  if (login[len - 1] == '\n')
  {
    login[--len] = '\0';
  }
  *login_len = len;

  printf("> Enter password: ");
  fgets(password, BUFF_LEN_MAX, stdin);

  len = strlen(password);
  if (password[len - 1] == '\n')
  {
    password[--len] = '\0';
  }
  *password_len = len;

  printf("> Select key length (128, 192, 256): ");
  ret = scanf("%d", &len);
  if (ret != 1)
  {
    goto EXIT;
  }

  switch(len)
  {
    case 128:
    case 192:
    case 256:
      *key_len = len / 8;
      break;
    default:
      ret = -1;
  }

EXIT:
  return ret;
}

int output(const char *type,
           const unsigned char *data, int data_len,
           const unsigned char *cipher, int cipher_len,
           const unsigned char *key, int key_len)
{
  int i;

  printf("--------------\n");
  printf("Generated key:\n");
  for (i = 0; i < key_len; i++)
  {
    printf("%x ", key[i]);
    if ((i + 1) % 16 == 0)
    {
      printf("\n");
    }
  }

  if (key_len == 24)
  {
    printf("\n");
  }

  printf("\n%s:\n%s\n", type, data);

  printf("Encrypted %s:\n", type);
  for (i = 0; i < cipher_len; i++)
  {
    printf("%x ", cipher[i]);
    if ((i + 1) % 16 == 0)
    {
      printf("\n");
    }
  }
  printf("\n");

  return 0;
}
