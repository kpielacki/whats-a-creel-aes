# What's a Creel AES Source

## About
This is the source code of the AES series created by What's a Creel. The video
series can be found [here](https://www.youtube.com/watch?v=K2Xfm0-owS4). I do
**not** take credit for this and I'm only posting it since it was requested in
the comment section. However, I did implement the decryption portion and added
a bit more context on what some of these functions do. As mentioned in the
beginning of the series this should **not** be used in any implementation and
is for the sake of understanding the inner workings of AES.

I tried to reorganize some of the code in a way that still closely resembles
the original. It should be noted this is for ECE AES-128. For larger bit keys
the process is very similar and mostly differs on the key expansion and number
of rounds. If you are more curious I recommend you view
[this](https://github.com/kokke/tiny-AES-c) implementation. It helped me when
trying to work out the decryption portion and supports different key sizes.

## Compiling
```
gcc print_hex.h lookup_boxes.h enc_arg_opts.h aes.h aes_key.h enc.c -o enc
gcc print_hex.h lookup_boxes.h dec_arg_opts.h aes.h aes_key.h dec.c -o dec
```

## Usage

### Key
Like in the video series the key is hardcoded and can be found in the aes_key.h
file.

### Encryption
```
$ ./enc -?
Usage: enc [OPTION...] message hex-print
Encrypts input message with ECB AES-128

  -h, --hex-print            Output encrypted message as hex
  -m, --message=This is an AES encrypted message!
                             Message to encrypt.
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```
- Binary output of test message
  * `$ ./enc`
- Hex output of test message
  * `$ ./enc -h`
- Enter your own message
  * `$ ./enc -m "This is a new message" -h`

### Decryption
```
$ ./dec -?
Usage: dec [OPTION...] message hex-print
Decrypts input message with ECB AES-128

  -m, --message=Input message as bytes
                             Message to decrypt.
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```
- Decryption of hard coded test message
  * `$ ./dec`
- Decrypt your own message read from binary
  * `$ ./enc -m "own message"`
