from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random


# Funkcje do konwersji kluczy
def public_key_to_rsa(public_key):
    e, n = public_key
    return RSA.construct((n, e))


def private_key_to_rsa(private_key):
    d, n = private_key
    return RSA.construct((n, 65537, d))


# Funkcja do szyfrowania pliku
def encrypt_file_crypto(input_file, output_file, public_key):
    rsa_key = public_key_to_rsa(public_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    key_size = rsa_key.size_in_bytes() - 11  # PKCS1 v1.5 padding

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = b''
    for i in range(0, len(plaintext), key_size):
        block = plaintext[i:i + key_size]
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block

    with open(output_file, 'wb') as f:
        f.write(ciphertext)


# Funkcja do deszyfrowania pliku
def decrypt_file_crypto(input_file, output_file, private_key):
    rsa_key = private_key_to_rsa(private_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    key_size = rsa_key.size_in_bytes()

    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    sentinel = Random.new().read(15 + key_size)  # Random sentinel for decryption
    plaintext = b''

    for i in range(0, len(ciphertext), key_size):
        block = ciphertext[i:i + key_size]
        decrypted_block = cipher.decrypt(block, sentinel)
        plaintext += decrypted_block

    with open(output_file, 'wb') as f:
        f.write(plaintext)


