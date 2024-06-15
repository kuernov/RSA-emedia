import unittest

from Crypto.Random import get_random_bytes

import key_generator

from RSA import RSA
from PNG_reader import PNG_reader



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
        self.png_reader.encrypt_idat(self.rsa, True, self.keys[0])
        # Step 3: Write the encrypted PNG to a file
        self.png_reader.write_png('encrypted_example.png')

        # Step 4: Read the encrypted PNG file
        self.png_reader = PNG_reader(mode='decrypt')
        self.png_reader.read_png('encrypted_example.png')

        # Step 5: Decrypt the IDAT chunk data
        self.png_reader.decrypt_idat(self.rsa,True, self.keys[1])

        # Step 6: Write the decrypted PNG to a file
        self.png_reader.write_png('decrypted_example.png', encrypted=False)

    def test_encrypt_decrypt_ofb(self):
        self.png_reader.read_png('2.png')

        self.png_reader.encrypt_idat(self.rsa, False, self.keys[0])
        # Step 3: Write the encrypted PNG to a file
        self.png_reader.write_png('encrypted_example_ofb.png')

        # Step 4: Read the encrypted PNG file
        self.png_reader = PNG_reader(mode='decrypt')
        self.png_reader.read_png('encrypted_example_ofb.png')

        # Step 5: Decrypt the IDAT chunk data
        self.png_reader.decrypt_idat(self.rsa, False, self.keys[0])

        # Step 6: Write the decrypted PNG to a file
        self.png_reader.write_png('decrypted_example_ofb.png', encrypted=False)






