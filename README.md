# kyber-k2so-python

This project is a Python translation of the Kyber (version 3) post-quantum IND-CCA2 Key Encapsulation Mechanism (KEM), originally implemented in Go by Symbolic Software. The library aims to provide an accessible Python interface for working with the Kyber cryptographic protocol, adhering to the post-quantum security principles.

## License

This project is released under the MIT License, consistent with the licensing of the original Go implementation by Symbolic Software.

## Requirements

- Python 3.6 or higher
- Numpy

## Installation

Clone the repo:
```bash
git clone https://github.com/afkaf/kyber-k2so-python.git
```

I will distribute it via PyPI soon.

## Usage Example

```python
from kyberk2so import kem_keypair_512, kem_encrypt_512, kem_decrypt_512

# Generate a keypair
sk, pk = kem_keypair_512()

# Encapsulate a secret
ct, ss_a = kem_encrypt_512(pk)

# Decapsulate the ciphertext
ss_b = kem_decrypt_512(ct, sk)
```

The above example illustrates the process of securely exchanging a 32-byte secret key using the Kyber-512 key encapsulation mechanism. It demonstrates generating a keypair, encapsulating a secret to produce a ciphertext, and then decapsulating the ciphertext on the receiving end to recover the shared secret key. Functions for Kyber-768 and Kyber-1024 are also available.

You can clone the project and run the usage example found in `example.py`.

## Acknowledgments

Thanks to Symbolic Software for their development of the original Kyber-K2SO library in Go. This Python project is a translation and adaptation of their work, intended to make the Kyber KEM accessible to Python developers interested in post-quantum cryptography. The original Go implementation by Symbolic Software can be found at [Symbolic Software's Kyber Repository](https://github.com/symbolicsoft/kyber-k2so).

## Disclaimer

This library is provided as-is, and it is not officially associated with Symbolic Software. It is a personal project aimed at providing post-quantum cryptographic tools for Python developers. While effort has been made to ensure accuracy and security, users should verify the security and suitability of this library for their projects.
