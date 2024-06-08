from Crypto.Util import number

class KeyGenerator:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.e = 65537
        
    def generate(self):
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.d = number.inverse(self.e, phi)
        public_key = (self.e, self.n)
        private_key = (self.d, self.n)
        return public_key, private_key