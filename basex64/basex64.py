"""
Module:         BaseX64
Description:    A simple cryptographic tool based on a Base64-like encoding scheme with dynamic XOR shifts.
Author:         Andrii Burkatskyi aka andr11b
Year:           2025
Version:        0.0.1.250102
License:        MIT License
Email:          4ndr116@gmail.com
Link:           https://github.com/codyverse/basex64
"""

import hashlib
import os
import argparse
import re
import random
import string
from collections import OrderedDict


def md5(file):
    """
    Calculate and return the MD5 checksum of the file.

    Args:
        file (str): Path to the file.

    Returns:
        str: MD5 checksum of the file.
    """
    hash_md5 = hashlib.md5()

    with open(file, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


class BaseX64:
    """
    Custom cipher class that implements encryption and decryption using Base64-like algorithm with shifts.

    Attributes:
        CHARSET (str): Character set used for encoding/decoding.
        key (str): Encryption/Decryption key.
        ivl (int): Length of the initialization vector.
        ivs (int): Length of the initialization vector slice.
        shifts (list): List of shifts based on the key.
        cache (OrderedDict): Cache for storing previously calculated shifts.
        cache_size (int): Maximum size of the cache.
    """
    CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    def __init__(self, key, ivl=16, ivs=0, cache_size=1000):
        """
        Initialize the cipher with a key, IV length, and cache size.

        Args:
            key (str): The key used for encryption and decryption.
            ivl (int): Length of the initialization vector. Default is 16.
            ivs (int): Slice of the IV to prepend them to the ciphertext. Default is 0.
            cache_size (int): Maximum size of the cache. Default is 1000.
        """
        self.key = hashlib.sha512(key.encode()).hexdigest()  # Hash the key to a fixed-length digest.
        self.key_shifts = [ord(c) for c in self.key]  # List of shifts derived from the key.
        self.ivl = max(8, min(abs(ivl), 128))  # Ensure IV length is between 8 and 128.
        self.ivs = abs(ivs) % self.ivl if abs(ivs) != self.ivl else self.ivl  # Normalize IV slice length.
        self.cache = OrderedDict()  # Ordered cache for storing shift results.
        self.cache_size = abs(cache_size)  # Maximum cache size.
        random.seed(self.key)  # Seed the random generator with the key for consistent randomness.
        self.CHARSET = ''.join(random.sample(self.CHARSET, len(self.CHARSET)))  # Shuffle the CHARSET.

    def _shifts(self, iv):
        """
        Calculate dynamic shifts based on IV and precomputed key shifts.

        Args:
            iv (str): Initialization vector.

        Returns:
            list: List of calculated shifts.
        """
        return [(shift ^ ord(iv[i % len(iv)])) for i, shift in enumerate(self.key_shifts)]

    def _cache(self, key, value):
        """
        Add a key-value pair to the cache, maintaining size limitations.

        Args:
            key (str): The key for the cache entry.
            value (str): The value for the cache entry.

        Returns:
            str: The cached value.
        """
        if len(self.cache) >= self.cache_size:  # If cache exceeds max size, remove the oldest entry.
            self.cache.popitem(last=False)

        self.cache[key] = value

        return value

    def encrypt(self, data):
        """
        Encrypt the given data using the custom cipher.

        Args:
            data (bytes): Data to be encrypted.

        Returns:
            bytes: The encrypted data.
        """
        if data == b'': return data  # Return empty data if input is empty.

        iv = hashlib.sha512(data).hexdigest()[:self.ivl]  # Generate IV based on the input data.
        shifts = self._shifts(iv)  # Generate dynamic shifts using XOR between the key and IV.

        binary = ''.join([bin(byte)[2:].zfill(8) for byte in data])  # Convert each char to 8-bit binary and combine.
        chunks = [binary[i:i + 6] for i in range(0, len(binary), 6)]  # Split binary string into 6-bit chunks.
        if chunks and len(chunks[-1]) < 6:  # Ensure that the last chunk is 6 bits.
            chunks[-1] = chunks[-1].ljust(6, '0')

        # Encrypt each 6-bit chunk and apply the shift.
        encrypted = ''
        for i, chunk in enumerate(chunks):
            shift = shifts[i % len(shifts)]  # Apply a cyclic shift pattern.
            key = f'{chunk}:{shift}'  # Create a key for caching.

            if key not in self.cache:  # Cache the encrypted character if not already present.
                self._cache(key, self.CHARSET[(int(chunk.ljust(6, '0'), 2) + shift) & 63])

            encrypted += self.cache[key]

        # Slice the IV based on the specified parameters.
        lcut = iv[:self.ivs]
        rcut = iv[self.ivs:]

        return (lcut + encrypted + rcut).encode()

    def decrypt(self, data):
        """
        Decrypt the given data using the custom cipher.

        Args:
            data (bytes): Data to be decrypted.

        Returns:
            bytes: The decrypted data.
        """
        if data == b'': return data  # Return empty data if input is empty.

        data = data.decode('utf-8')  # Decode the input data from UTF-8.

        rcut_len = self.ivl - self.ivs  # Determine the length of the right part of the IV.
        lcut = data[:self.ivs]  # Slice the IV parts
        rcut = data[len(data) - rcut_len:]

        data = data[self.ivs:len(data) - rcut_len]  # Extract the actual encrypted data.

        shifts = self._shifts(lcut + rcut)  # Create unique shifts using XOR between the key and the IV.

        # Convert BaseX64 string to binary (each character from CHARSET is 6 bits).
        xdata = ''.join([bin(self.CHARSET.index(c))[2:].zfill(6) for c in data if c in self.CHARSET])

        # Apply XOR and reconstruct original 8-bit binary (considering the shift).
        binary = ''
        for i in range(0, len(xdata), 6):
            chunk = xdata[i:i + 6]
            shift = shifts[i // 6 % len(shifts)]  # Apply corresponding shift for the chunk

            index = (int(chunk, 2) - shift + 64) & 63  # Unshift and map back to the original 6-bit value.
            binary += bin(index)[2:].zfill(6)  # Convert 6-bit back to 8-bit binary (pad with zeros).

        decrypted = bytearray()

        for i in range(0, len(binary), 8):  # Convert 8-bit binary back to bytes.
            byte = binary[i:i + 8]

            if len(byte) == 8:
                decrypted.append(int(byte, 2))

        return bytes(decrypted)


def main():
    """
    Main function to handle command-line arguments and perform encryption or decryption.
    """
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files using a custom Base64-like algorithm.')

    parser.add_argument('-i', '--input', help='Path to the input file.')
    parser.add_argument('-o', '--output', help='Path to the output file.')
    parser.add_argument('--inline', help='Inline data to encrypt/decrypt.')
    parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the input file.')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the input file.')
    parser.add_argument('-k', '--key', help='Encryption/Decryption key.')
    parser.add_argument('-f', '--force', action='store_true', help='Force rewrite output file if exists.')
    parser.add_argument(
        '-l',
        '--vector-length',
        type=int,
        default=16,
        help='Length of the initialization vector (IV), range: 8-128. Default: 16.'
    )
    parser.add_argument(
        '-s',
        '--vector-slice',
        type=int,
        default=0,
        help='Slice n symbols from the IV and prepend them to the ciphertext. Default: 0.'
    )
    parser.add_argument('--self-test', type=int, help='Self-testing by processing 1024 random bytes n times.')

    args = parser.parse_args()

    if args.self_test:
        for i in range(0, args.self_test):
            r_data = os.urandom(1024)
            r_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            r_ivl = random.randint(8, 128)
            r_ivs = random.randint(0, r_ivl)

            cipher = BaseX64(r_key, r_ivl, r_ivs)

            encrypted = cipher.encrypt(r_data)
            decrypted = cipher.decrypt(encrypted)

            if hashlib.md5(r_data).hexdigest() != hashlib.md5(decrypted).hexdigest():
                raise RuntimeError(f"Self-test failed with ivl={r_ivl} and r_ivs={r_ivs}")

        return print('Self-test completed successfully!')

    if args.input and args.inline:
        parser.error('You cannot specify both -i (input file) and --inline (inline data) at the same time.')

    if args.input and args.output and args.input == args.output:
        parser.error('You cannot specify the same input and output file names, use different please.')

    if args.input and not os.path.isfile(args.input):
        parser.error(f"Input file '{args.input}' does not exist.")

    if not (8 <= args.vector_length <= 128):
        parser.error("IV length must be between 8 and 128 bytes.")

    cipher = BaseX64(args.key, args.vector_length, args.vector_slice)

    if not (args.encrypt ^ args.decrypt):  # XOR to ensure one and only one action is selected.
        parser.error('You must specify either -e/--encrypt or -d/--decrypt.')

    if args.inline:
        if args.encrypt:
            print(cipher.encrypt(args.inline.encode()).decode('utf-8'))
        elif args.decrypt:
            decrypted = cipher.decrypt(args.inline.encode())

            try:
                print(decrypted.decode('utf-8'))
            except:
                if not args.output:  # If it is not possible to decode to UTF-8, ask to specify the output file.
                    parser.error('The decrypted data is binary. Please specify an output file using -o.')
                else:
                    # If there is an output file, display an error that needs to be written to the file.
                    if args.output and os.path.exists(args.output) and args.decrypt and not args.force:
                        parser.error(f"Output file '{args.output}' already exists. Decryption will overwrite it.")

                    with open(args.output, 'wb') as f:
                        f.write(decrypted)

                    print(f"Binary data written to {args.output}.")

        return True

    base, ext = os.path.splitext(args.input)
    checksum = re.search(r'([^.]+)\.([a-f0-9]{32})\.(.*)', args.input)

    outfile = args.output
    if not outfile:
        if args.decrypt and checksum:
            outfile = f"{checksum.group(1)}{ext}"
        else:
            suffix = f".{md5(args.input)}" if args.encrypt else '.decrypted'
            outfile = f'{base}{suffix}{ext}'

    if outfile and os.path.exists(outfile) and not args.force:
        parser.error(f"Output file '{outfile}' already exists. Decryption will overwrite it.")

    with open(args.input, 'rb') as input, open(outfile, 'wb') as output:
        line = input.readline()
        while line:
            if line.endswith(b'\n'):
                line = line.rstrip(b'\n')
                nl = True
            else:
                nl = False

            if args.encrypt:
                data = cipher.encrypt(line)
            elif args.decrypt:
                data = cipher.decrypt(line)

            output.write(data if (nl == False) else (data + b'\n'))

            line = input.readline()

    error = ''
    if args.decrypt and checksum and checksum.group(2) != md5(outfile):
        error = ', but the checksum does not match'

    print(f"Operation completed{error}. Output file: {outfile}")


if __name__ == '__main__':
    main()
