#ifndef AES_H
#define AES_H


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lookup_boxes.h"


/* Function: key_expansion_core
 * ----------------------------
 * Sets "in" to rotation of all in bytes to the left and XOR with RCon index i.
 *
 * Rotates 4 bytes to the left and moves 8 MSB bits to 8 LSB slot then
 * multiplies by RCon index i.
 *
 * in: bytes to be rotated
 * i: RCon index to multiply by
 */
void key_expansion_core(unsigned char* in, unsigned char i) {
  unsigned int * q = (unsigned int *) in;
  // Left rotate bytes
  *q = (*q >> 8 | ((*q & 0xff) << 24));

  in[0] = s_box[in[0]]; in[1] = s_box[in[1]];
  in[2] = s_box[in[2]]; in[3] = s_box[in[3]];

  // RCon XOR
  in[0] ^= rcon[i];
}


/* Function: key_expansion
 * -----------------------
 * Takes 16 byte input key and expands to 176 bytes.
 *
 * The key is expanded to 176 bytes which allows for 10 key uses.
 *
 * input_key: 16 byte key used for expansion
 * expanded_key: is set to resulting expanded key
 */
void key_expansion(unsigned char* input_key, unsigned char* expanded_keys) {
  // Set first 16 bytes to input_key
  for (int i = 0; i < 16; i++)
    expanded_keys[i] = input_key[i];

  unsigned int bytes_generated = 16;
  int rcon_iteration = 1;
  unsigned char temp[4];

  // Generate the next 160 bytes
  while (bytes_generated < 176) {
    // Read 4 bytes for the core
    for (int i = 0; i < 4; i++)
      temp[i] = expanded_keys[i + bytes_generated - 4];

    // Perform the core once for each 16 byte key
    if (bytes_generated % 16 == 0)
      key_expansion_core(temp, rcon_iteration++);

    // XOR temp with [bytes_generated-16], and store in expanded_keys
    for (unsigned char a = 0; a < 4; a++) {
      expanded_keys[bytes_generated] = expanded_keys[bytes_generated - 16] ^ temp[a];
      bytes_generated++;
    }
  }
}


/* Function: sub_bytes
 * -------------------
 * Substitutes each 16 state bytes with corresponding byte in Rijndael S-Box.
 *
 * Understanding Cryptography by Christof Paar and Jan Pelzl pg 90
 *     This process introduces confusion to the data, i.e., it assures that
 *     changes in individual state bits propagate quickly across the data path.
 *
 * state: bytes to be substituted
 */
void sub_bytes(unsigned char* state) {
  // Substitute each state value with another byte in the Rijndael S-Box
  for (int i = 0; i < 16; i++)
    state[i] = s_box[state[i]];
}


/* Function: inv_sub_bytes
 * -----------------------
 * Substitutes each 16 state bytes with corresponding byte in inverse Rijndael S-Box.
 *
 * state: bytes to be substituted
 */
void inv_sub_bytes(unsigned char* state) {
  // Substitute each state value with another byte in the Rijndael S-Box
  for (int i = 0; i < 16; i++)
    state[i] = inv_s_box[state[i]];
}


/* Function: shift_rows
 * --------------------
 * Shifts each row of a 4x4 matrix to the left by it's row number - 1.
 *
 * Any entries the are shifted outside the matrix bounds is rotated back to the
 * right of the row.
 *
 * Row 1 no shift.
 * Row 2 shift left once.
 * Row 3 shift left twice.
 * Row 4 shift left three times.
 *
 * This function along with mix columns introduce diffusion. Diffusion attempts
 * to disguise properties of the input message. An example of this would be the
 * character "e" is most common in the English language so you would want to
 * design cipher in a way that someone attempting to break the cipher would not
 * be able to use some character frequency analysis to obtain more information.
 *
 * state: 16 byte array representing 4x4 matrix where first 4 entries represent
 *        the first column
 */
void shift_rows(unsigned char* state) {
  unsigned char tmp[16];

  // First row don't shift (idx = idx)
  tmp[0] = state[0];
  tmp[4] = state[4];
  tmp[8] = state[8];
  tmp[12] = state[12];

  // Second row shift right once (idx = (idx + 4) % 16)
  tmp[1] = state[5];
  tmp[5] = state[9];
  tmp[9] = state[13];
  tmp[13] = state[1];

  // Third row shift right twice (idx = (idx +/- 8) % 16)
  tmp[2] = state[10];
  tmp[6] = state[14];
  tmp[10] = state[2];
  tmp[14] = state[6];

  // Fourth row shift right three times (idx = (idx - 4) % 16)
  tmp[3] = state[15];
  tmp[7] = state[3];
  tmp[11] = state[7];
  tmp[15] = state[11];

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}


/* Function: inv_shift_rows
 * ------------------------
 * Shifts each row of a 4x4 matrix to the right by it's row number - 1.
 *
 * Any entries the are shifted outside the matrix bounds is rotated back to the
 * left of the row.
 *
 * Row 1 no shift.
 * Row 2 shift right once.
 * Row 3 shift right twice.
 * Row 4 shift right three times.
 *
 * state: 16 byte array representing 4x4 matrix where first 4 entries represent
 *        the first column
 */
void inv_shift_rows(unsigned char* state) {
  unsigned char tmp[16];

  // First row don't shift (idx = idx)
  tmp[0] = state[0];
  tmp[4] = state[4];
  tmp[8] = state[8];
  tmp[12] = state[12];

  // Second row shift right once (idx = (idx - 4) % 16)
  tmp[1] = state[13];
  tmp[5] = state[1];
  tmp[9] = state[5];
  tmp[13] = state[9];

  // Third row shift right twice (idx = (idx +/- 8) % 16)
  tmp[2] = state[10];
  tmp[6] = state[14];
  tmp[10] = state[2];
  tmp[14] = state[6];

  // Fourth row shift right three times (idx = (idx + 4) % 16)
  tmp[3] = state[7];
  tmp[7] = state[11];
  tmp[11] = state[15];
  tmp[15] = state[3];

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}


/* Function: mix_columns
 * ---------------------
 * Takes a 16 char byte array and transforms to new 16 byte char array that
 * represents the GF(256) matrix multiplication of a known matrix times the
 * state. The byte array represents a 4x4 matrix where the first 4 entries
 * represents the first column.
 *
 * Known Matrix:
 *     [[2, 3, 1, 1],
 *      [1, 2, 3, 1],
 *      [1, 1, 2, 3],
 *      [3, 1, 1, 2]]
 *
 * This operation essentially performs the following for each row in GF(256)
 * where d_i represents the new column entry of index i and b_i represents the
 * input state column entry of index i.
 *     d_0 = (2*b_0) + (3*b_1) + (1*b_2) + (1*b_3)
 *     d_1 = (1*b_0) + (2*b_1) + (3*b_2) + (1*b_3)
 *     d_2 = (1*b_0) + (1*b_1) + (2*b_2) + (3*b_3)
 *     d_3 = (3*b_0) + (1*b_1) + (1*b_2) + (2*b_3)
 *
 * This function along with shift rows introduce diffusion. Diffusion attempts
 * to disguise properties of the input message. An example of this would be the
 * character "e" is most common in the English language so you would want to
 * design cipher in a way that someone attempting to break the cipher would not
 * be able to use some character frequency analysis to obtain more information.
 *
 * For more details visit https://en.wikipedia.org/wiki/Rijndael_MixColumns
 *
 * state: 16 unsigned char byte array to transform
 */
void mix_columns(unsigned char* state) {
  // Dot product and byte mod of state

  unsigned char tmp[16];
  // Column 1 entries
  tmp[0] = (unsigned char) (mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
  tmp[1] = (unsigned char) (state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
  tmp[2] = (unsigned char) (state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
  tmp[3] = (unsigned char) (mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);
 
  // Column 2 entries
  tmp[4] = (unsigned char) (mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
  tmp[5] = (unsigned char) (state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
  tmp[6] = (unsigned char) (state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
  tmp[7] = (unsigned char) (mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);
 
  // Column 3 entries
  tmp[8] = (unsigned char) (mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
  tmp[9] = (unsigned char) (state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
  tmp[10] = (unsigned char) (state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
  tmp[11] = (unsigned char) (mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);
 
  // Column 4 entries
  tmp[12] = (unsigned char) (mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
  tmp[13] = (unsigned char) (state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
  tmp[14] = (unsigned char) (state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
  tmp[15] = (unsigned char) (mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}


/* Function: inv_mix_columns
 * -------------------------
 * Takes a 16 char byte array and transforms to new 16 byte char array that
 * represents the inverse of the mix_columns function. This essentially takes
 * a known inverse matrix and multiples it against the state. The byte array
 * represents a 4x4 matrix where the first 4 entries represents the first
 * column.
 *
 * Known Inverse Matrix:
 *     [[14, 11, 13,  9],
 *      [ 9, 14, 11, 13],
 *      [13,  9, 14, 11],
 *      [11, 13,  9, 14]]
 *
 * This operation essentially performs the following for each row in GF(256)
 * where d_i represents the new column entry of index i and b_i represents the
 * input state column entry of index i.
 *     d_0 = (14*b_0) + (11*b_1) + (13*b_2) + ( 9*b_3)
 *     d_1 = ( 9*b_0) + (14*b_1) + (11*b_2) + (13*b_3)
 *     d_2 = (13*b_0) + ( 9*b_1) + (14*b_2) + (11*b_3)
 *     d_3 = (11*b_0) + (13*b_1) + ( 9*b_2) + (14*b_3)
 *
 * For more details visit https://en.wikipedia.org/wiki/Rijndael_MixColumns
 *
 * state: 16 unsigned char byte array to transform
 */
void inv_mix_columns(unsigned char* state) {
  unsigned char tmp[16];

  // Column 1
  tmp[0] = (unsigned char) (mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]]);
  tmp[1] = (unsigned char) (mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]]);
  tmp[2] = (unsigned char) (mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]]);
  tmp[3] = (unsigned char) (mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]]);
 
  // Column 2
  tmp[4] = (unsigned char) (mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]]);
  tmp[5] = (unsigned char) (mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]]);
  tmp[6] = (unsigned char) (mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]]);
  tmp[7] = (unsigned char) (mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]]);
 
  // Column 3
  tmp[8] = (unsigned char) (mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]]);
  tmp[9] = (unsigned char) (mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]]);
  tmp[10] = (unsigned char) (mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]]);
  tmp[11] = (unsigned char) (mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]]);
 
  // Column 4
  tmp[12] = (unsigned char) (mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]]);
  tmp[13] = (unsigned char) (mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]]);
  tmp[14] = (unsigned char) (mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]]);
  tmp[15] = (unsigned char) (mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]]);

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}


/* Function: add_round_key
 * -----------------------
 * Set each index in 16 byte state array to XOR of state[index] and round_key[index]
 *
 * XOR the round key with the current state.
 *
 * Sometimes the round key is referred to as subkey.
 *
 * state: 16 unsigned char byte array to be updated
 * round_key: 16 unsigned char byte array to XOR against
 */
void add_round_key(unsigned char* state, unsigned char* round_key) {
  for (int i = 0; i < 16; i++)
    state[i] ^= round_key[i];
}


/* Function: aes_encrypt
 * ---------------------
 * Encrypts message using 9 round ECB AES-128 encryption and given expanded key.
 *
 * Encryption Process:
 *     First Round:
 *         --------------------
 *         Add Round Key [First 16 Bytes]
 *         --------------------
 *
 *     Next 9 Rounds:
 *         --------------------------------
 *         Sub Bytes with S-Box
 *         Left Shift Rows
 *         Mix Columns
 *         Add Round Key [16 * (Round + 1)]
 *         --------------------------------
 *
 *     Final Round:
 *         --------------------------------
 *         Sub Bytes with S-Box
 *         Left Shift Rows
 *         Add Round Key [Last 16 Bytes]
 *         --------------------------------
 *
 * Notice that the final round does not call the mix columns function. This is
 * so the encryption and decryption scheme is symetric.
 *
 * message: 16 byte message to encrypt
 * expanded_key: 172 byte expanded key for cipher
 */
char * aes_encrypt(unsigned char* message, unsigned char* expanded_key) {
  unsigned char state[16];

  // Take only the first 16 characters of the message
  for (int i = 0; i < 16; i++)
     state[i] = message[i];

  const unsigned int round_cnt = 9;
  add_round_key(state, expanded_key);

  for (int i = 0; i < round_cnt; i++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, expanded_key + (16 * (i + 1)));
  }

  // Final round
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, expanded_key + 160);

  char * enc_msg  = (char *) malloc(16);
  memcpy(enc_msg, state, 16);
  return enc_msg;
}


/* Function: aes_decrypt
 * ---------------------
 * Decrypts ECB AES-128 encrypted message for given expanded_key.
 *
 * Due to the nature of the decryption process being a reverse of the
 * encryption process it's possible to compare each round between encryption
 * and decryption to see if they are the same. In other words inversing the
 * first round should yield the same result as the second to last encryption
 * round which can be useful for dubugging.
 *
 * Note that AES is not based on a Feistel network which means all layers must
 * be inverted. In other words left shift rows becomes right shift rows, mix
 * columns becomes inverse mix columns, sub bytes becomes inverse sub bytes,
 * etc.
 *
 * Decryption Process:
 *     First Round:
 *         --------------------------------
 *         Add Round Key [Last 16 Bytes]
 *         --------------------------------
 *
 *     Next 9 Rounds:
 *         --------------------------------
 *         Right Shift Rows
 *         Sub Bytes with Inverse S-Box
 *         Add Round Key [16 * (9 - Round)]
 *         Inverse Mix Columns
 *         --------------------------------
 *
 *     Final Round:
 *         --------------------------------
 *         Right Shift Rows
 *         Sub Bytes with Inverse S-Box
 *         Add Round Key [0]
 *         --------------------------------
 *
 * message: 16 byte message to encrypt
 * expanded_key: 172 byte expanded key for cipher
 */
char * aes_decrypt(unsigned char* message, unsigned char* expanded_key) {
  unsigned char state[16];

  // Take only the first 16 characters of the message
  for (int i = 0; i < 16; i++)
     state[i] = message[i];

  const int round_cnt = 9;
  add_round_key(state, expanded_key + 160);

  for (int i = round_cnt; i > 0; i--) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, expanded_key + (16 * i));
    inv_mix_columns(state);
  }
  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, expanded_key);

  char * dec_msg = (char *) malloc(16);
  memcpy(dec_msg, state, 16);
  return dec_msg;
}


/* Function: right_pad_str
 * -----------------------
 * right pads remainder msg mod pad_len with 0
 *
 * str: string to pad
 * pad_len: divisable length top pad to
 *
 * returns: pointer to padded message
 */
char * right_pad_str(char * str, unsigned int pad_len) {
  const unsigned int str_len = strlen(str);
  unsigned int padded_str_len = str_len;
  if (padded_str_len % pad_len != 0)
    padded_str_len = (padded_str_len / pad_len + 1) * pad_len;

  unsigned char * padded_str = malloc(padded_str_len);
  for (int i = 0; i < padded_str_len; i++) {
    if (i >= str_len) padded_str[i] = 0;
    else padded_str[i] = str[i];
  }
  return padded_str;
}


#endif
