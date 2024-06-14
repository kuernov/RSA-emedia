import zlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
class CryptoRsa:
    def __init__(self, rsa_key=None):
        self.rsa_private_key, self.rsa_public_key = self.generate_keys(2048)

    @staticmethod
    def generate_keys(key_size=2048):

        key = RSA.generate(key_size)
        rsa_private_key = key
        rsa_public_key = key.publickey()
        return rsa_private_key, rsa_public_key

    @staticmethod
    def read_png(file):
        chunks = []

        with open(file, 'rb') as f:
            # Sprawdzenie podpisu PNG (8 bajtów)
            signature = f.read(8)
            if signature != b'\x89PNG\r\n\x1a\n':
                raise ValueError("Not a valid PNG file")
            while True:
                length = int.from_bytes(f.read(4), "big")
                chunk_type = f.read(4)
                chunk_data = f.read(length)
                f.read(4) #read crc
                chunks.append((chunk_type, chunk_data))
                if chunk_type == b"IEND":
                    break
        return signature, chunks

    @staticmethod
    def write_png(file, signature, chunks):
        with open(file, "wb") as f:
            f.write(signature)
            for chunk_type, chunk_data in chunks:
                f.write(len(chunk_data).to_bytes(4, "big"))
                f.write(chunk_type)
                f.write(chunk_data)
                crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
                f.write(crc.to_bytes(4, "big"))

    def encrypt_data(self, data):
        session_key = get_random_bytes(16)  # Klucz AES o długości 16 bajtów (128 bitów)

        # Użycie PKCS#1 v1.5 do szyfrowania klucza sesyjnego
        cipher_rsa = PKCS1_v1_5.new(self.rsa_public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Szyfrowanie danych przy użyciu AES w trybie ECB
        cipher_aes = AES.new(session_key, AES.MODE_ECB)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher_aes.encrypt(padded_data)

        # Zwracanie zaszyfrowanego klucza sesyjnego oraz zaszyfrowanych danych
        return enc_session_key + ciphertext

    def decrypt_data(self, data):
        enc_session_key_size = self.rsa_private_key.size_in_bytes()
        enc_session_key = data[:enc_session_key_size]
        # Odszyfrowanie klucza sesyjnego
        cipher_rsa = PKCS1_v1_5.new(self.rsa_private_key)
        sentinel = get_random_bytes(16)
        session_key = cipher_rsa.decrypt(enc_session_key, sentinel)
        if session_key == sentinel:
            raise ValueError("Odszyfrowanie klucza sesyjnego nie powiodło się")
        ciphertext = data[enc_session_key_size:]
        cipher_aes = AES.new(session_key, AES.MODE_ECB)
        padded_data = cipher_aes.decrypt(ciphertext)
        return unpad(padded_data, AES.block_size)

    def encrypt_rsa(self, input_file, output_file):
        signature, chunks = self.read_png(input_file)
        encrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                decompressed_data = zlib.decompress(chunk_data)
                encrypted_data = self.encrypt_data(decompressed_data)
                compressed_encrypted_data = zlib.compress(encrypted_data)
                encrypted_chunks.append((chunk_type, compressed_encrypted_data))
            else:
                encrypted_chunks.append((chunk_type, chunk_data))
        self.write_png(output_file, signature, encrypted_chunks)


    def decrypt_rsa(self, input_file, output_file):

        signature, chunks = self.read_png(input_file)
        decrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                decompressed_data = zlib.decompress(chunk_data)
                decrypted_data = self.decrypt_data(decompressed_data)
                compressed_decrypted_data = zlib.compress(decrypted_data)
                decrypted_chunks.append((chunk_type, compressed_decrypted_data))
            else:
                decrypted_chunks.append((chunk_type, chunk_data))
        self.write_png(output_file, signature, decrypted_chunks)

    def encrypt_compressed_rsa(self, input_file, output_file):
        signature, chunks = self.read_png(input_file)
        encrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                compressed_data = zlib.compress(chunk_data)
                padded_data = pad(compressed_data, AES.block_size)
                encrypted_data = self.encrypt_data(padded_data)
                encrypted_chunks.append((chunk_type, encrypted_data))
            else:
                encrypted_chunks.append((chunk_type, chunk_data))
            self.write_png(output_file, signature, encrypted_chunks)

    def decrypt_compressed_rsa(self, input_file, output_file):

        signature, chunks = self.read_png(input_file)
        decrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                decrypted_data = self.decrypt_data(chunk_data)
                unpadded_data = unpad(decrypted_data, AES.block_size)
                decompressed_decrypted_data = zlib.decompress(unpadded_data)
                decrypted_chunks.append((chunk_type, decompressed_decrypted_data))
            else:
                decrypted_chunks.append((chunk_type, chunk_data))
        self.write_png(output_file, signature, decrypted_chunks)


encryptor = CryptoRsa()

input_file = "2.png"
output_file_encrypted = "encrypted.png"
output_file_decrypted = "decrypted.png"
output_file_compressed_encrypted = "encrypted_compressed.png"
output_file_compressed_decrypted = "decrypted_compressed.png"

encryptor.encrypt_rsa(input_file, output_file_encrypted)

encryptor.decrypt_rsa(output_file_encrypted, output_file_decrypted)

encryptor.encrypt_compressed_rsa(input_file, output_file_compressed_encrypted)

encryptor.decrypt_compressed_rsa(output_file_compressed_encrypted, output_file_compressed_decrypted)
