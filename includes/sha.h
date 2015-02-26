#define HMAC_OUT_LEN 20

/*
 *
 *	Function to use SHA1 with incremental HMAC
 *
 * */
void incremental_hmac ( unsigned char* str, unsigned char* key, size_t keylen ) {
  int           i;
  HMAC_CTX	ctx;
  unsigned int	len;
  unsigned char	out[20];
  
  HMAC_Init(&ctx, key, keylen, EVP_sha1());
  HMAC_Update(&ctx, str, 4);
  HMAC_Final(&ctx, out, &len);
  for ( i = 0; i < len; i++ ) fprintf(stderr, "%02x", out[i]);
  fprintf(stderr, "\n");

  HMAC_cleanup(&ctx);
}

/*
 *
 *	Function to generate the hash values of the SHA128
 *
 * */
unsigned char* digest_message ( const EVP_MD* type, unsigned char* in, unsigned long n, unsigned int *outlen ) {
  EVP_MD_CTX	   ctx;
  unsigned char*   ret;

  EVP_DigestInit(&ctx, type);
  EVP_DigestUpdate(&ctx, in, n);
  if ( !(ret = (unsigned char *)malloc(EVP_MD_CTX_size(&ctx))) ) return 0;
  EVP_DigestFinal(&ctx, ret, outlen);
  return ret;
}

/*
 *
 *	SHA128 From openssl lib
 *
 * */
void sha_128 ( unsigned char* str ) {
  int 	           i;
  unsigned int	   ol;
  unsigned char*   r;

  r = digest_message(EVP_sha1(), str, strlen(str), &ol);

  for ( i = 0; i < ol; i++ ) fprintf(stderr, "%02x", r[i]);
  fprintf(stderr, "\n");
  free(r);
}

/*
 *
 * SHA512 From openssl lib
 *
 * */
void sha_512 ( unsigned char* str ) {
  int 		   i;
  SHA512_CTX	   ctx;
  unsigned char	   result[SHA512_DIGEST_LENGTH];

  SHA512_Init(&ctx);
  SHA512_Update(&ctx, str, strlen(str));
  SHA512_Final(result, &ctx);

  for ( i = 0; i < SHA512_DIGEST_LENGTH; i++ ) fprintf(stderr, "%02x", result[i]);
  fprintf(stderr, "\n");
}

/*
 *
 *	SHA256 From openssl lib
 *
 * */
void sha_256 ( unsigned char* str ) {
  int 			i;
  SHA256_CTX		ctx;
  unsigned char 	result[SHA256_DIGEST_LENGTH];

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, str, strlen(str));
  SHA256_Final(result, &ctx);

  for ( i = 0; i < SHA256_DIGEST_LENGTH; i++ ) fprintf(stderr, "%02x", result[i]);
  fprintf(stderr, "\n");
}

/*
 *
 * Incremental SHA1
 *
 * */
void incr_sha1 ( unsigned char* str1, unsigned char* str2 ) {
  int 	i;
  SHA_CTX ctx;
  unsigned char result[SHA_DIGEST_LENGTH];

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, str1, strlen(str1));
  SHA1_Update(&ctx, str2, strlen(str2));
  SHA1_Final(result, &ctx);

  for (i = 0; i < SHA_DIGEST_LENGTH; i++) fprintf(stderr, "%02x", result[i]); 
  fprintf(stderr, "\n");
}

/*
 *
 * HMAC-SHA1 Generation Key Function. It takes two arguments
 * 1 - the string and the key.
 *
 * */
void make_key_hmac_sha1 ( unsigned char* data, unsigned char* key ) {
  int i;
  unsigned char* result;
  unsigned int len = strlen(data);

  result = (unsigned char *)malloc(sizeof(char) * len);

  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);

  HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
  HMAC_Update(&ctx, (unsigned char *)&data, strlen(data));
  HMAC_Final(&ctx, result, &len);
  HMAC_CTX_cleanup(&ctx);

  for ( i = 0; i != len; i++ )
    fprintf(stderr, "%02x", (unsigned int)result[i]);
  fprintf(stderr, "\n");

  free(result);
}

