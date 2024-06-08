import key_generator
import RSA as rsa

generator = key_generator.KeyGenerator()
rsa = rsa.RSA(generator.key_size)

keys = generator.generate()

message = b"Example text for encryption using RSA."
ciphertext = rsa.encrypt_rsa(message, keys[0])
print("Ciphertext:", ciphertext)

# Deszyfrowanie wiadomości
decrypted_message = rsa.decrypt_rsa(ciphertext, keys[1])
print("Decrypted message:", decrypted_message)

if decrypted_message == message:
    print("Correct!")



block = b'Test block'
encrypted_block = rsa.encrypt_rsa_block(block, keys[0])
decrypted_block = rsa.decrypt_rsa_block(encrypted_block, keys[1])
print("Encrypted block:", encrypted_block)
print("Decrypted block:", decrypted_block)
if decrypted_message == message:
    print("Correct2!")