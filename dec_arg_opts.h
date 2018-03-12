#ifndef DEC_ARG_OPTS_H
#define DEC_ARG_OPTS_H


#include <argp.h>


/* A description of the arguments we accept. */
static char dec_args_doc[] = "message hex-print";


/* Program documentation. */
static char dec_doc[] = "Decrypts input message with ECB AES-128";


typedef struct dec_arguments {
  char * args[2];
  char * message;
} dec_arguments;


// TODO: Add option to take hex code input
static struct argp_option dec_options[] = {
  {"message", 'm', "Input message as bytes", 0, "Message to decrypt."},
  {0}
};


static error_t dec_parse_opt(int key, char *arg, struct argp_state *state) {
  struct dec_arguments *input = state->input;

  int i = 0;
  unsigned char * c;
  switch (key) {
    case 'm':
      input->message = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static struct argp dec_argp = {dec_options, dec_parse_opt, dec_args_doc, dec_doc};


#endif
