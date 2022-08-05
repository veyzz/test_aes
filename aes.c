#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include "defines.h"
#include "aes.h"

int generate_key(const unsigned char *data, int data_len,
                 unsigned char *key, int key_len)
{
  int ret = 0;

  /* MD5 returns 128-bit value */
  MD5(data, strlen(data), key);

  switch(key_len)
  {
    case 16:
      /* Nothing to do*/
      break;
    case 24:
    case 32:
      memcpy(key + 16, key, key_len - 16);
      break;
    default:
      ret = -1;
  }

  key[key_len] = '\0';

  return ret;
}

int encrypt(const unsigned char *data, int data_len,
            const unsigned char *key, int key_len,
            unsigned char *cipher, int *cipher_len)
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
  cipher[*cipher_len] = '\0';

EXIT:
  /* Clean up */
  if (ctx)
  {
    EVP_CIPHER_CTX_free(ctx);
  }

  return ret;
}

int decrypt(const unsigned char *cipher, int cipher_len,
            const unsigned char *key, int key_len,
            unsigned char *data, int *data_len)
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
  data[*data_len] = '\0';

EXIT:
  /* Clean up */
  if (ctx)
  {
    EVP_CIPHER_CTX_free(ctx);
  }

  return ret;
}

/* returns 0 if correct */
int test_correctness(const unsigned char *data, int data_len,
                     const unsigned char *encr_data, int encr_data_len,
                     const unsigned char *key, int key_len)
{
  int ret = 0;
  unsigned char decr_data[BUFF_LEN_MAX];
  int decr_data_len;

  ret = decrypt(encr_data, encr_data_len,
                key, key_len,
                decr_data, &decr_data_len);

  if (ret != 0)
  {
    goto EXIT;
  }

  if (decr_data_len != data_len)
  {
    ret = -1;
    goto EXIT;
  }

  if (0 != strncmp(data, decr_data, data_len))
  {
    ret = -1;
    goto EXIT;
  }

EXIT:
  return ret;
}
