#ifndef PRINT_HEX_H
#define PRINT_HEX_H


#include <stdio.h>


/* Function: print_hex
 * -------------------
 * Takes 16 bytes and prints as hex code.
 *
 * msg: bytes to be printed
 */
void print_hex(char * msg) {
  for (int i = 0; i < 16; i++)
    printf("%02X ", (unsigned char) *(msg+i));
  putchar('\n');
}


#endif
