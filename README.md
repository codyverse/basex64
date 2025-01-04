# BaseX64

## What is it?

The **BaseX64** script is a simple cryptographic tool that uses dynamic `XOR` for encryption, combined with a `Base64`-like encoding scheme, ensuring that only printable `ASCII` characters are used. Additionally, it supports line-by-line ciphering, which ensures that only the corresponding lines in the ciphertext are updated after changes in the original data and re-encryption.

Why reinvent the wheel? I needed a `Python` tool that would allow storing encrypted data on distributed version control systems such as `Git`, while meeting the following criteria:

  - Using only `ASCII` characters.
  - Ensuring that small changes in the source do not cause a total change in the ciphertext.

While `AES-CTR` could fulfill these requirements, `Python` does not have native `AES` support in its standard library. To avoid relying on third-party libraries, I decided to implement a custom solution.

## Main features

  - Encrypt and decrypt files using a Base64-like scheme with dynamic XOR shifts.
  - Customizable initialization vector (IV) length and divided store mode.
  - Handling for both inline data and file input/output.
  - Ability to handle IV-based dynamic shifts for encryption/decryption.
  - Command-line interface (CLI) for simple usage.

## Installation

- from GitHub
  ```bash
  git clone https://github.com/codyverse/basex64.git
  cd basex64
  ```

- via PIP
  ```bash
  pip install basex64
  ```

## Usage

### Options:

```
  -h, --help          Show this help message and exit.
  -i, --input         Path to the input file.
  -o, --output        Path to the output file.
      --inline        Inline data to encrypt/decrypt.
  -e, --encrypt       Encrypt the input file or data.
  -d, --decrypt       Decrypt the input file or data.
  -k, --key           Encryption/Decryption key.
  -l, --vector-length Length of the initialization vector (IV). Default: 16.
  -s, --vector-slice  Slice n symbols from the IV and prepend them to the ciphertext. Default: 0.
  -f, --force         Force rewrite of output file if it exists.
      --self-test     Self-test mode to verify encryption/decryption integrity with random data.
```

### Examples

- Encrypt the `input.txt` file and save the output as `output.enc`:
  ```
  python3 basex64.py -e -k your_secret_key -i input.txt -o output.enc
  ```

- Decrypt the `output.enc` file and save the decrypted data to `output.txt`:
  ```
  python3 basex64.py -d -k your_secret_key -i output.enc -o output.txt
  ```

- Encrypt inline data:
  ```
  python3 basex64.py -e -k your_secret_key --inline "Hello, World!"
  ```

- Decrypt inline data:
  ```
  python3 basex64.py -d -k your_secret_key --inline "20c+U4QAm0AjyUhe3F374d794a95cdcfd8"
  ```

- Perform self-testing (generating random data):
  ```
  python3 basex64.py --self-test 100
  ```
  This will run 100 iterations of random data encryption and decryption with random parameters to ensure the integrity of the cipher.

- Encrypt inline data with the IV slicing, for example with, `-s 8`:
  ```
  python3 basex64.py -e -k your_secret_key --inline "Hello, World!" -s 8
  374d794a20c+U4QAm0AjyUhe3F95cdcfd8
  ```
  In this case, `8` IV characters are added at the beginning, and the remainder is left at the end of the ciphertext. Obviously, if specify `--vector-length 16` and `--vector-slice 16`, the entire IV will be moved to the beginning of the ciphertext.

  This changes the structure of the ciphertext and adds an additional layer of security, since without knowing the encryption parameters, an attacker cannot directly recover the IV from the ciphertext.
  **Important**: To decrypt the ciphertext, you must specify the same `--vector-slice` value used during encryption.

## Contributing

Feel free to contribute by submitting issues or pull requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.
