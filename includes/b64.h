static char b64table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+/";

/*
 *
 * Function to Calculate Length
 *
 * */
unsigned int calcDecodeLength ( const char* b64input ) {
  int len = strlen(b64input);
  int padding = 0;
  
  if ( b64input[len - 1] == '=' && b64input[len - 2] == '=' )
    padding = 2;
  else if ( b64input[len - 1] == '=' )
    padding = 1;
  
  return (int)len * 0.75 - padding;
}

/*
 *
 * Base64 Decoding functions from the OPENSSL-C-API
 *
 * */
unsigned int base64_decode ( unsigned char* b64message, unsigned char** buffer ) {
  BIO *bio, *b64;
  int decodelen = calcDecodeLength( b64message ), len = 0;
  
  *buffer = (char*)malloc(decodelen + 1);
  FILE* stream = fmemopen(b64message, strlen(b64message), "r");
  
  b64 = BIO_new( BIO_f_base64() );
  bio = BIO_new_fp( stream, BIO_NOCLOSE );
  bio = BIO_push( b64, bio );
  BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL );
  len = BIO_read( bio, *buffer, strlen(b64message) );
  
  (*buffer)[len] = '\0';
  
  BIO_free_all( bio );
  fclose( stream );
  
  return 0;
}

/*
 *
 * Base64 encoding function: encodes six bits of data at a time
 * Char in the output will be a numeric digit, a letter, a forward
 * slash, a plus, or the equal sign.
 *
 * */
unsigned char* base64_encode ( unsigned char* input, size_t len, int wrap ) {
  unsigned char *output, *p;
  size_t i = 0, mod = len % 3, toalloc;
  
  toalloc = (len / 3) * 4 + (3 - mod) % 3 + 1;
  if ( wrap ) {
    toalloc += len / 57;
    if ( len % 57 ) toalloc++;
  }
  
  p = output = (unsigned char* )malloc(((len / 3) + (mod ? 1 : 0)) * 4 + 1);
  if (!p) return 0;
  
  while ( i < len - mod ) {
    *p++ = b64table[input[i++] >> 2];
    *p++ = b64table[((input[i -1] << 4) | (input[i] >> 4)) & 0x3f];
    *p++ = b64table[((input[i] << 2) | (input[i + 1] >> 6)) & 0x3f];
    *p++ = b64table[input[i + 1] & 0x3f];
    i += 2;
    if ( wrap && !(i % 57)) *p++ = '\n';
  }
  if (!mod) {
    if ( wrap && i % 57 ) *p++ = '\n';
    *p = 0;
    return output;
  } else {
    *p++ = b64table[input[i++] >> 2];
    *p++ = b64table[((input[i - 1] << 4) | (input[i] >> 4)) & 0x3f];
    if ( mod == 1 ) {
      *p++ = '=';
      *p++ = '=';
      if (wrap) *p++ = '\n';
      *p = 0;
      return output;
    } else {
      *p++ = b64table[(input[i] << 2) & 0x3f];
      *p++ = '=';
      if (wrap) *p++ = '\n';
      *p = 0;
      return output;
    }
  }
}
