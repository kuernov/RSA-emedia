import unittest
import key_generator

from RSA import RSA
from PNG_reader import PNG_reader
from CryptoRsa import encrypt_file_crypto, decrypt_file_crypto


class TestPNGEncryption(unittest.TestCase):
    def setUp(self):
        self.generator = key_generator.KeyGenerator()
        self.rsa = RSA(self.generator.key_size)
        self.png_reader = PNG_reader(mode='encrypt')
        self.keys = self.generator.generate()


    def test_encryption(self):
        message = b"Example text for encryption using RSA."
        ciphertext = self.rsa.encrypt_rsa(message, self.keys[0])
        print("Ciphertext:", ciphertext)

        # Deszyfrowanie wiadomości
        decrypted_message = self.rsa.decrypt_rsa(ciphertext, self.keys[1])
        print("Decrypted message:", decrypted_message)

        assert(decrypted_message == message)

    def test_block_encryption(self):
        block = b'Test block'
        encrypted_block = self.rsa.encrypt_rsa_block(block, self.keys[0])
        decrypted_block = self.rsa.decrypt_rsa_block(encrypted_block, self.keys[1])
        print("Encrypted block:", encrypted_block)
        print("Decrypted block:", decrypted_block)

    def test_encrypt_decrypt_png(self):
        self.png_reader.read_png('2.png')
        self.png_reader.encrypt_idat(self.rsa, self.keys[0])
        # Step 3: Write the encrypted PNG to a file
        self.png_reader.write_png('encrypted_example.png')

        # Step 4: Read the encrypted PNG file
        self.png_reader = PNG_reader(mode='decrypt')
        self.png_reader.read_png('encrypted_example.png')

        # Step 5: Decrypt the IDAT chunk data
        self.png_reader.decrypt_idat(self.rsa, self.keys[1])

        # Step 6: Write the decrypted PNG to a file
        self.png_reader.write_png('decrypted_example.png', encrypted=False)

        input_file = '2.png'
        encrypted_file = 'encrypted_example_crypto.png'
        decrypted_file = 'decrypted_example_crypto.png'

        encrypt_file_crypto(input_file, encrypted_file, self.keys[0])
        decrypt_file_crypto(encrypted_file, decrypted_file, self.keys[1])

        with open('2.png', 'rb') as f:
            original_data = f.read()
        with open('decrypted_example.png', 'rb') as f:
            decrypted_data = f.read()


