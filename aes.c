#include <openssl/evp.h>
#include "aes.h"

int encrypt(const char *data, int data_len,
            const char *key, int key_len,
            char *cipher, int *cipher_len)
{
  int ret = 0;
  EVP_CIPHER_CTX* ctx;
  const EVP_CIPHER *cipher_algo;
  int len, slen;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    ret = -1;
    goto EXIT;
  }

  switch(key_len)
  {
    case 16:
      cipher_algo = EVP_aes_128_cbc();
      break;
    case 24:
      cipher_algo = EVP_aes_192_cbc();
      break;
    case 32:
      cipher_algo = EVP_aes_256_cbc();
      break;
    default:
      ret = -1;
      goto EXIT;
  }

  if (1 != EVP_EncryptInit_ex(ctx, cipher_algo, NULL, key, NULL))
  {
    ret = -1;
    goto EXIT;
  }

  if (1 != EVP_EncryptUpdate(ctx, cipher, &len, data, data_len))
  {
    ret = -1;
    goto EXIT;
  }

  slen = len;

  if (1 != EVP_EncryptFinal_ex(ctx, cipher + slen, &len))
  {
    ret = -1;
    goto EXIT;
  }

  slen += len;

  *cipher_len = slen;

EXIT:
  /* Clean up */
  if (ctx)
  {
    EVP_CIPHER_CTX_free(ctx);
  }

  return ret;
}

int decrypt(const char *cipher, int cipher_len,
            const char *key, int key_len,
            char *data, int *data_len)
{
  int ret = 0;
  EVP_CIPHER_CTX* ctx;
  const EVP_CIPHER *cipher_algo;
  int len, slen;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    ret = -1;
    goto EXIT;
  }

  switch(key_len)
  {
    case 16:
      cipher_algo = EVP_aes_128_cbc();
      break;
    case 24:
      cipher_algo = EVP_aes_192_cbc();
      break;
    case 32:
      cipher_algo = EVP_aes_256_cbc();
      break;
    default:
      ret = -1;
      goto EXIT;
  }

  if (1 != EVP_DecryptInit_ex(ctx, cipher_algo, NULL, key, NULL))
  {
    ret = -1;
    goto EXIT;
  }

  if (1 != EVP_DecryptUpdate(ctx, data, &len, cipher, cipher_len))
  {
    ret = -1;
    goto EXIT;
  }

  slen = len;

  if (1 != EVP_DecryptFinal_ex(ctx, data + slen, &len))
  {
    ret = -1;
    goto EXIT;
  }

  slen += len;

  *data_len = slen;

EXIT:
  /* Clean up */
  if (ctx)
  {
    EVP_CIPHER_CTX_free(ctx);
  }

  return ret;
}
