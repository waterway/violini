/*
 *
 * Simple XOR-ing
 *
 * */
unsigned char* simple_xor ( unsigned char* data, unsigned char* key ) {
  int i;
  unsigned int data_len = strlen(data);

  for ( i = 0; i < data_len; i++ )
    data[i] ^= key[i];

  return data;
}
