import struct
import zlib

from Crypto.Random import get_random_bytes

import RSA

class PNG_reader:
    def __init__(self, mode):
        self.mode = mode
        self.IDAT_data = b''
        self.chunks = []
        self.iv = get_random_bytes(16)

    def read_png(self, filepath):
        with open(filepath, 'rb') as f:
            # Sprawdzenie nagłówka pliku PNG
            header = f.read(8)
            if header != b'\x89PNG\r\n\x1a\n':
                raise ValueError('Not a PNG file')

            while True:
                # Odczytanie długości chunka (4 bajty, big-endian)
                length_data = f.read(4)
                if len(length_data) == 0:
                    break  # Koniec pliku

                length = struct.unpack('>I', length_data)[0]

                chunk_type = f.read(4)

                chunk_data = f.read(length)

                chunk_expected_crc = struct.unpack('>I', f.read(4))[0]

                chunk_actual_crc = zlib.crc32(chunk_data, zlib.crc32(struct.pack('>4s', chunk_type)))

                if chunk_expected_crc != chunk_actual_crc:
                    raise Exception(f"Chunk checksum failed for {chunk_type}")

                self.chunks.append((chunk_type, chunk_data))

                if chunk_type == b"IEND":
                    break
                elif chunk_type == b"IDAT":
                    self.IDAT_data += chunk_data

    def _decompress_idat(self):
        return zlib.decompress(self.IDAT_data)

    def _compress_idat(self, data):
        return zlib.compress(data)

    def write_png(self, output_file, encrypted=True):
        """
        Zapisuje zaszyfrowany lub odszyfrowany plik PNG.

        :param output_file: Ścieżka do pliku wyjściowego.
        :param encrypted: Flaga wskazująca, czy zapisać zaszyfrowane czy odszyfrowane dane.
        """
        with open(output_file, "wb") as f_out:
            # Zapisanie sygnatury PNG
            PngSignature = b"\x89PNG\r\n\x1a\n"
            f_out.write(PngSignature)

            # Zapisanie wszystkich chunków oprócz IDAT i IEND
            for chunk_type, chunk_data in self.chunks:
                if chunk_type == b"IDAT":
                    if encrypted:
                        data_to_write = self.encrypted_compressed_data
                    else:
                        data_to_write = self.decrypted_compressed_data

                    f_out.write(struct.pack(">I", len(data_to_write)))
                    f_out.write(chunk_type)
                    f_out.write(data_to_write)
                    crc = zlib.crc32(data_to_write, zlib.crc32(chunk_type))
                    f_out.write(struct.pack(">I", crc))
                elif chunk_type != b"IEND":
                    f_out.write(struct.pack(">I", len(chunk_data)))
                    f_out.write(chunk_type)
                    f_out.write(chunk_data)
                    crc = zlib.crc32(chunk_data, zlib.crc32(chunk_type))
                    f_out.write(struct.pack(">I", crc))

            # Zapisanie chunku IEND
            f_out.write(struct.pack(">I", 0))
            f_out.write(b"IEND")
            crc = zlib.crc32(b"IEND")
            f_out.write(struct.pack(">I", crc))

    def encrypt_idat(self, rsa_encryptor, is_ecb, public_key):
        decompressed_data = self._decompress_idat()
        if is_ecb:
            encrypted_data = rsa_encryptor.encrypt_rsa(decompressed_data, public_key)
        else:
            encrypted_data = rsa_encryptor.encrypt_ofb(decompressed_data, self.iv, public_key)
        self.encrypted_compressed_data = self._compress_idat(encrypted_data)

    def decrypt_idat(self, rsa_encryptor, is_ecb, private_key):
        decompressed_data = self._decompress_idat()
        if is_ecb:
            decrypted_data = rsa_encryptor.decrypt_rsa(decompressed_data, private_key)
        else:
            decrypted_data = rsa_encryptor.decrypt_ofb(decompressed_data, self.iv, private_key)
        self.decrypted_compressed_data = self._compress_idat(decrypted_data)

    def encrypt_idat_ofb(self, rsa_encryptor, iv, public_key):
        decompressed_data = self._decompress_idat()
        encrypted_data = rsa_encryptor.encrypt_ofb(decompressed_data, iv, public_key)
        self.encrypted_compressed_data = self._compress_idat(encrypted_data)

    def decrypt_idat_ofb(self, rsa_encryptor, iv, public_key):
        decompressed_data = self._decompress_idat()
        decrypted_data = rsa_encryptor.decrypt_ofb(decompressed_data, iv, public_key)
        self.decrypted_compressed_data = self._compress_idat(decrypted_data)
