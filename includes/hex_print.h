#define BYTES_PER_GROUP 4
#define GROUPS_PER_LINE 4
#define BYTES_PER_LINE (BYTES_PER_GROUP * GROUPS_PER_LINE)

void print_hex(unsigned char* prefix, unsigned char* str, int len) {
  unsigned long i, j, preflen = 0;

  if (prefix) {
    fprintf(stderr, "%s", prefix);
    preflen = strlen(prefix);
  }

  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x", str[i]);
    if (((i % BYTES_PER_LINE) == (BYTES_PER_LINE - 1)) && ((i + 1) != len)) {

    } else if ((i % BYTES_PER_GROUP) == (BYTES_PER_GROUP - 1)) putchar(' ');
  }
  putchar('\n');
}
