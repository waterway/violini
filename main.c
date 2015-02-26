/*
 *    
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "includes/hex_print.h"
#include "includes/b64.h"
#include "includes/sha.h"
#include "includes/simple_xor.h"

const char* program_name; /* program name */
const char* const short_options = "hoxedmstqai:v"; /* argv short options */
/* argv long options */
const struct option long_options[] = {
  { "help", 0, NULL, 'h' },
  { "simple-xor", 2, NULL, 'o' },
  { "print-hex", 1, NULL, 'x' },
  { "encode-base64", 1, NULL, 'e' },
  { "decode-base64", 1, NULL, 'd' },
  { "make-key-hmac-sha1", 2, NULL, 'm'},
  { "incr-sha1", 2, NULL, 's'},
  { "incr-hmac-sha1", 2, NULL, 'i' },
  { "sha-128", 1, NULL, 'a' },
  { "sha-256", 1, NULL, 't' },
  { "sha-512", 1, NULL, 'q' },
  { "version", 0, NULL, 'v' },
  { NULL, 0, NULL, 0 }
};

void print_banner ( void ) {
  fprintf(stderr, "\n");                                                               
  fprintf(stderr, "  _/      _/  _/_/_/    _/_/    _/        _/_/_/  _/      _/   \n");
  fprintf(stderr, " _/      _/    _/    _/    _/  _/          _/    _/_/    _/    \n");
  fprintf(stderr, "_/      _/    _/    _/    _/  _/          _/    _/  _/  _/     \n");
  fprintf(stderr, " _/  _/      _/    _/    _/  _/          _/    _/    _/_/      \n");
  fprintf(stderr, "  _/      _/_/_/    _/_/    _/_/_/_/  _/_/_/  _/      _/       \n");
  fprintf(stderr, "                                                         v0.01 \n\n");
}

/*
 *
 * Function to print usage
 *
*/
void print_usage ( FILE* stream, int exit_code ) {
  print_banner();
  fprintf( stderr, "Usage: %s options [ data ... ]\n", program_name );
  fprintf( stderr, 
	   "\n"
	   "  -o, --simple-xor [str] [key]           XOR a string with a key.\n"
	   "  -x, --print-hex [str]                  Print Keys as Hexadecimal.\n"
	   "  -e, --encode-base64 [str]              Encode a String to Base64.\n"
	   "  -d, --decode-base64 [str]              Decode a base64 encoded message to String.\n"
	   "  -m, --make-key-hmac-sha1 [str] [key]   Generate a key for a short time usage HMAC-SHA1.\n"
	   "  -s, --incr-sha1 [str] [str]            Generate a Incremental SHA1 Hash Data.\n"
	   "  -i, --incr-hmac [str] [key]            Generate a Incremental Interface to Hash Data.\n"
	   "  -a, --sha-128 [str]                    Generate a SHA 128 Hash Data.\n"
	   "  -t, --sha-256 [str]                    Generate a SHA 256 Hash Data.\n"
	   "  -q, --sha-512 [str]                    Generate a SHA 512 Hash Data.\n"
	   "  -h, --help                             Display this usage information.\n"
	   "  -v, --version                          Print version.\n\n");
  exit( exit_code );
}

/*
 *
 * Function to print version
 *
 */
void print_version ( FILE* stream, int exit_code ) {
  print_banner();
  fprintf(stderr, "Violin Version v0.01\n");
  exit(0);
}

int main ( int argc, char *argv[] ) {
  int next_option;
  int verbose;
  char prefix[] = "";
  unsigned char* base64decodeoutput;
  unsigned char* hmac_sha1_key = "";
  unsigned char* xor_key = "";
  
  program_name = argv[0];
  
  if ( argc < 2 )
    print_usage( stdout, 0 );
  else {
    do {
      next_option = getopt_long( argc, argv, short_options, long_options, NULL );
      switch ( next_option ) {
      case 'h':
	print_usage( stdout, 0 );
	
      case 'o':
	if ( !argv[2] ) {
	  print_usage( stdout, 0 );
	} else {
	  if ( !argv[3] )
	    fprintf(stderr, "%s\n", simple_xor(argv[2], xor_key));
	  else
	    fprintf(stderr, "%s\n", simple_xor(argv[2], argv[3]));
	}
	break;
      case 'x':
	print_hex(prefix, argv[2], strlen(argv[2]));
	break;
      case 'e':
	fprintf(stderr, "%s", base64_encode( argv[2], strlen(argv[2]), 1));
	break;
      case 'd':
	base64_decode( argv[2], &base64decodeoutput );
	fprintf(stderr, "%s\n", base64decodeoutput);
	break;
      case 'v':
	print_version( stdout, 0 );
	break;
      case 'm':
	if ( !argv[2] ) {
	  print_usage( stdout, 0 );
	} else {
	  if ( !argv[3] )
	    make_key_hmac_sha1( argv[2], hmac_sha1_key );
	  else
	    make_key_hmac_sha1( argv[2], argv[3] );
	}
	break;
      case 's':
	if ( !argv[2] )
	  print_usage( stdout, 0 );
	else {
	  if ( !argv[3] )
	    incr_sha1( argv[2], "");
	  else
	    incr_sha1( argv[2], argv[3] );
	}
	break;
      case 't':
	sha_256( argv[2] );
	break;
      case 'q':
	sha_512( argv[2] );
	break;
      case 'a':
	sha_128( argv[2] );
	break;
      case 'i':
	if ( !argv[2] )
	  print_usage( stdout, 0 );
	else {
	  if ( !argv[3] )
	    print_usage( stdout, 0 );
	  else
	    incremental_hmac( argv[2], argv[3], strlen(argv[3]));
	}
	break;
      case '?':
	print_usage( stderr, 1 );
      case -1:
	break;
      default:
	abort();
      }
    } while ( next_option != -1 );
  }
  
  return EXIT_SUCCESS;
}
/* END */
