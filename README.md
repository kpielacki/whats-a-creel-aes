# What's a Creel AES Source

## About
This is the source code of the AES series created by What's a Creel. The video
series can be found [here](https://www.youtube.com/watch?v=K3Xfm0-owS4). I do
**not** take credit for this and I'm only posting it since it was requested in
the comment section. However, I did implement the decryption portion and added
a bit more context on what some of these functions do.

I tried to reorganize some of the code in a way that still closely resembles
the original. It should be noted this is for ECE AES-128. For larger bit keys
the process is very similar and mostly differs on the key expansion and number
of rounds. If you are more curious I recommend you view
[this](https://github.com/kokke/tiny-AES-c) implementation. It helped me when
trying to work out the decryption portion and supports different key sizes.

## Warning
As mentioned in the beginning of the series this should **not** be used in any
implementation and is for the sake of understanding the operations of AES. One
type of attack mentioned by the author is cache-timing attacks where response
times can leak information regarding the key. Many processors also include
their own implementation of AES with a new instruction that vastly improves
performance and according to current research should be safe from these types
of attacks.

Another reason to not base any real world applications on this is the fact that
AES-ECB is not semantically secure. Comparing two ciphertexts or looking for
repetitive information within a single ciphertext can leak plaintext
information. A good explanation can be found
[here](https://crypto.stackexchange.com/questions/20941/why-shouldnt-i-use-ecb-encryption).

## Compiling
```
make
```

## Usage

### Key
Like in the video series the key is hardcoded and can be found in the aes_key.h
file.

### Encryption
```
$ ./bin/enc -?
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
  * `$ ./bin/enc`
- Hex output of test message
  * `$ ./bin/enc -h`
- Enter your own message
  * `$ ./bin/enc -m "This is a new message" -h`

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
  * `$ ./bin/dec`
- Decrypt your own message read from binary
  * `$ ./bin/dec -m "own message"`
