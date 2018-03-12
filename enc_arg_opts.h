#ifndef ENC_ARG_OPTS_H
#define ENC_ARG_OPTS_H


#include <argp.h>


/* A description of the arguments we accept. */
static char enc_args_doc[] = "message hex-print";


/* Program documentation. */
static char enc_doc[] = "Encrypts input message with ECB AES-128";


typedef struct enc_arguments {
  char * args[2];
  char * message;
  int as_hex;
} enc_arguments;


static struct argp_option enc_options[] = {
  {"message", 'm', "This is an AES encrypted message!", 0, "Message to encrypt."},
  {"hex-print", 'h', 0, 0, "Output encrypted message as hex"},
  {0}
};


static error_t enc_parse_opt(int key, char *arg, struct argp_state *state) {
  struct enc_arguments *input = state->input;

  switch (key) {
    case 'm':
      input->message = arg;
      break;
    case 'h':
      input->as_hex = 1;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static struct argp enc_argp = {enc_options, enc_parse_opt, enc_args_doc, enc_doc};


#endif
