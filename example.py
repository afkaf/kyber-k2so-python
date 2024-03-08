from kyberk2so import kem_keypair_512, kem_encrypt_512, kem_decrypt_512

# Generate a keypair
sk, pk = kem_keypair_512()

# Encapsulate a secret
ct, ss_a = kem_encrypt_512(pk)

# Decapsulate the ciphertext
ss_b = kem_decrypt_512(ct, sk)