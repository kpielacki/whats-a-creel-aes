#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "aes_key.h"
#include "enc_arg_opts.h"
#include "print_hex.h"


int main(int argc, char * argv[]) {
  static enc_arguments arguments;

  // Default values
  arguments.message = "This is a message we will encrypt with AES!";
  arguments.as_hex = 0;
  argp_parse(&enc_argp, argc, argv, 0, 0 , &arguments);

  char * padded_msg = right_pad_str(arguments.message, 16);
  int padded_msg_len = strlen(arguments.message);
  if (padded_msg_len % 16)
    padded_msg_len = (padded_msg_len / 16 + 1) * 16;

  // expand key to 176 bytes
  unsigned char expanded_key[176];
  key_expansion(aes_key, expanded_key);

  // Iterate padded message in blocks of 16 bytes and encrypt
  char * enc_msg;
  for (int i = 0; i < padded_msg_len; i+=16) {
    // encrypt message
    enc_msg = aes_encrypt(padded_msg+i, expanded_key);
    if (arguments.as_hex) print_hex(enc_msg);
    else printf("%s", enc_msg);
    free(enc_msg);
  }
  if (!arguments.as_hex) putchar('\n');

  free(padded_msg);

  return 0;
}
