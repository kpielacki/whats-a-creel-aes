#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "aes_key.h"
#include "dec_arg_opts.h"
#include "print_hex.h"


// Hex representation of test message
unsigned char def_msg_bytes[48] = {
  0XB6, 0X4B, 0X27, 0XBB, 0X16, 0X15, 0XA6, 0XF5, 0X32, 0X18, 0X6C, 0XC5, 0XFA, 0X94, 0XB5, 0X5E,
  0X5C, 0X54, 0XEA, 0X1B, 0XDF, 0X97, 0X1E, 0X3D, 0XE3, 0X1B, 0XFC, 0X02, 0X75, 0X22, 0X76, 0X52,
  0XD5, 0X7B, 0XD5, 0X42, 0XBA, 0X0F, 0X68, 0X50, 0XCD, 0XFD, 0X59, 0XB8, 0XEB, 0X0E, 0X83, 0XD1
};


int main(int argc, char * argv[]) {
  static dec_arguments arguments;

  // Default values
  arguments.message = def_msg_bytes;
  argp_parse(&dec_argp, argc, argv, 0, 0 , &arguments);

  char * padded_msg = right_pad_str(arguments.message, 16);
  int padded_msg_len = strlen(arguments.message);
  if (padded_msg_len % 16)
    padded_msg_len = (strlen(arguments.message) / 16 + 1) * 16;

  // expand key to 176 bytes
  unsigned char expanded_key[176];
  key_expansion(aes_key, expanded_key);

  // Iterate padded message in blocks of 16 bytes and decrypt
  char * dec_msg;

  // TODO: For some reason excluding this prints binary
  putchar('\n');
  for (int i = 0; i < padded_msg_len; i+=16) {
    // decrypt message
    dec_msg = aes_decrypt(padded_msg+i, expanded_key);
    printf("%s", dec_msg);
    free(dec_msg);
  }
  putchar('\n');

  return 0;
}
