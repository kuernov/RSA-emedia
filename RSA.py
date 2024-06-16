import os


class RSA:

    def __init__(self, key_size):
        self.key_size = key_size

    def pkcs_padding(self, data, block_size):
        """
        Realizuje PKCS#1 v1.5 padding dla danych wejściowych.

        :param data: Dane do paddingu (w bajtach).
        :param block_size: Rozmiar bloku (w bajtach), np. 128 dla 1024-bitowego RSA.
        :return: Dane z paddingiem.
        """
        # Sprawdzenie długości danych
        data_length = len(data)
        max_data_length = block_size - 11  # 1 bajt na 0x00, 2 bajty na 0x02 i 8 bajtów na PS

        if data_length > max_data_length:
            raise ValueError(f"Data is too long for the given block size (max {max_data_length} bytes).")

        # Generowanie PS (padding string) - musi być różny od zera
        ps_length = block_size - data_length - 3
        ps = b''
        while len(ps) < ps_length:
            new_byte = os.urandom(1)
            if new_byte != b'\x00':
                ps += new_byte

        # Konstruowanie pełnego bloku z paddingiem
        padded_data = b'\x00' + b'\x02' + ps + b'\x00' + data

        return padded_data

    def pkcs_unpadding(self, data):
        """
        Usuwa PKCS#1 v1.5 padding z danych wejściowych.

        :param data: Dane z paddingiem (w bajtach).
        :return: Dane bez paddingu.
        """
        # Weryfikacja poprawności paddingu
        if len(data) < 11 or data[0] != 0x00 or data[1] != 0x02:
            raise ValueError("Invalid PKCS#1 v1.5 padding.")

        # Znalezienie indeksu pierwszego bajtu o wartości 0x00 po 0x02
        index = data.find(b'\x00', 2)
        if index == -1:
            raise ValueError("Invalid PKCS#1 v1.5 padding.")

        # Usunięcie paddingu
        unpadded_data = data[index + 1:]

        return unpadded_data

    def encrypt_rsa_block(self, block, public_key):
        e, n = public_key
        block_int = int.from_bytes(block, byteorder='big')
        encrypted_block_int = pow(block_int, e, n)
        encrypted_block = encrypted_block_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        return encrypted_block

    def decrypt_rsa_block(self, block, private_key):
        d, n = private_key
        block_int = int.from_bytes(block, byteorder='big')
        decrypted_block_int = pow(block_int, d, n)
        decrypted_block = decrypted_block_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        return decrypted_block

    # Szyfrowanie wiadomości
    def encrypt_rsa(self, message, public_key):
        n = public_key[1]
        block_size = (n.bit_length() + 7) // 8 - 11  # Adjust for padding
        ciphertext = []

        # Encrypt each block
        for i in range(0, len(message), block_size):
            block = message[i:i + block_size]
            padded_block = self.pkcs_padding(block, block_size + 11)
            encrypted_block = self.encrypt_rsa_block(padded_block, public_key)
            ciphertext.extend(encrypted_block)

        return bytes(ciphertext)

    def encrypt_ofb(self, plaintext, iv, public_key):
        e, n = public_key
        ciphertext = []
        feedback = iv
        for i in range(0, len(plaintext), self.key_size // 8 - 1):
            output_block = pow(int.from_bytes(feedback, byteorder="big"), e, n)
            output_bytes = output_block.to_bytes(self.key_size // 8, byteorder="big")
            block = plaintext[i: i + self.key_size // 8 - 1]
            encrypted_block = bytes(
                [x ^ y for x, y in zip(block, output_bytes[: len(block)])]
            )
            ciphertext.extend(encrypted_block)
            feedback = output_bytes
        return bytes(ciphertext)

    def decrypt_ofb(self, ciphertext, iv, public_key):

        return self.encrypt_ofb(ciphertext, iv, public_key)

    # Deszyfrowanie wiadomości
    def decrypt_rsa(self, ciphertext, private_key):
        n = private_key[1]
        block_size = (n.bit_length() + 7) // 8
        decrypted_message = []

        # Decrypt each block
        for i in range(0, len(ciphertext), block_size):
            block = ciphertext[i:i + block_size]
            decrypted_block = self.decrypt_rsa_block(block, private_key)
            unpadded_block = self.pkcs_unpadding(decrypted_block)
            decrypted_message.extend(unpadded_block)

        return bytes(decrypted_message)